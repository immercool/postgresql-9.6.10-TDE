/*-------------------------------------------------------------------------
 *
 * copydir.c
 *	  copies a directory
 *
 * Portions Copyright (c) 1996-2016, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *	While "xcopy /e /i /q" works fine for copying directories, on Windows XP
 *	it requires a Window handle which prevents it from working when invoked
 *	as a service.
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/copydir.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "catalog/catalog.h"
#include "storage/copydir.h"
#include "storage/encryption.h"
#include "storage/fd.h"
#include "storage/smgr.h"
#include "miscadmin.h"


/*
 * copydir: copy a directory
 *
 * RelFileNode values must specify tablespace and database oids for source
 * and target to support re-encryption if necessary. relNode value in provided
 * structs will be clobbered.
 */
void
copydir(char *fromdir, char *todir, RelFileNode *fromNode, RelFileNode *toNode)
{
	DIR		   *xldir;
	struct dirent *xlde;
	char		fromfile[MAXPGPATH * 2];
	char		tofile[MAXPGPATH * 2];

	Assert(!encryption_enabled || (fromNode != NULL && toNode != NULL));


	if (mkdir(todir, S_IRWXU) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create directory \"%s\": %m", todir)));

	xldir = AllocateDir(fromdir);
	if (xldir == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open directory \"%s\": %m", fromdir)));

	while ((xlde = ReadDir(xldir, fromdir)) != NULL)
	{
		struct stat fst;

		/* If we got a cancel signal during the copy of the directory, quit */
		CHECK_FOR_INTERRUPTS();

		if (strcmp(xlde->d_name, ".") == 0 ||
			strcmp(xlde->d_name, "..") == 0)
			continue;

		snprintf(fromfile, sizeof(fromfile), "%s/%s", fromdir, xlde->d_name);
		snprintf(tofile, sizeof(tofile), "%s/%s", todir, xlde->d_name);

		if (lstat(fromfile, &fst) < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not stat file \"%s\": %m", fromfile)));

		if (S_ISREG(fst.st_mode))
		{
			int oidchars;
			ForkNumber forkNum;
			int segment;

			/*
			 * For encrypted databases we need to reencrypt files with new
			 * tweaks.
			 */
			if (encryption_enabled &&
				parse_filename_for_nontemp_relation(xlde->d_name,
													&oidchars, &forkNum, &segment))
			{
				char oidbuf[OIDCHARS+1];
				memcpy(oidbuf, xlde->d_name, oidchars);
				oidbuf[oidchars] = '\0';

				/* We scribble over the provided RelFileNodes here */
				fromNode->relNode = toNode->relNode = atol(oidbuf);
				copy_file(fromfile, tofile, fromNode, toNode, forkNum, forkNum, segment);
			}
			else
				copy_file(fromfile, tofile, NULL, NULL, 0, 0, 0);
		}
	}
	FreeDir(xldir);

	/*
	 * Be paranoid here and fsync all files to ensure the copy is really done.
	 * But if fsync is disabled, we're done.
	 */
	if (!enableFsync)
		return;

	xldir = AllocateDir(todir);
	if (xldir == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open directory \"%s\": %m", todir)));

	while ((xlde = ReadDir(xldir, todir)) != NULL)
	{
		struct stat fst;

		if (strcmp(xlde->d_name, ".") == 0 ||
			strcmp(xlde->d_name, "..") == 0)
			continue;

		snprintf(tofile, sizeof(tofile), "%s/%s", todir, xlde->d_name);

		/*
		 * We don't need to sync subdirectories here since the recursive
		 * copydir will do it before it returns
		 */
		if (lstat(tofile, &fst) < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not stat file \"%s\": %m", tofile)));

		if (S_ISREG(fst.st_mode))
			fsync_fname(tofile, false);
	}
	FreeDir(xldir);

	/*
	 * It's important to fsync the destination directory itself as individual
	 * file fsyncs don't guarantee that the directory entry for the file is
	 * synced. Recent versions of ext4 have made the window much wider but
	 * it's been true for ext3 and other filesystems in the past.
	 */
	fsync_fname(todir, true);
}

/*
 * copy one file. If decryption and reencryption is needed specify
 * relfilenodes for source and target. */
void
copy_file(char *fromfile, char *tofile, RelFileNode *fromNode,
		  RelFileNode *toNode, ForkNumber fromForkNum, ForkNumber toForkNum,
		  int segment)
{
	char	   *buffer;
	int			srcfd;
	int			dstfd;
	int			nbytes;
	int			bytesread;
	BlockNumber blockNum = segment*RELSEG_SIZE;
	off_t		offset;
	off_t		flush_offset;

	/* Size of copy buffer (read and write requests) */
#define COPY_BUF_SIZE (8 * BLCKSZ)

	/*
	 * Size of data flush requests.  It seems beneficial on most platforms to
	 * do this every 1MB or so.  But macOS, at least with early releases of
	 * APFS, is really unfriendly to small mmap/msync requests, so there do it
	 * only every 32MB.
	 */
#if defined(__darwin__)
#define FLUSH_DISTANCE (32 * 1024 * 1024)
#else
#define FLUSH_DISTANCE (1024 * 1024)
#endif

	/* Use palloc to ensure we get a maxaligned buffer */
	buffer = palloc(COPY_BUF_SIZE);

	/*
	 * Open the files
	 */
	srcfd = OpenTransientFile(fromfile, O_RDONLY | PG_BINARY, 0);
	if (srcfd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m", fromfile)));

	dstfd = OpenTransientFile(tofile, O_RDWR | O_CREAT | O_EXCL | PG_BINARY,
							  S_IRUSR | S_IWUSR);
	if (dstfd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create file \"%s\": %m", tofile)));

	/*
	 * Do the data copying.
	 */
	flush_offset = 0;
	for (offset = 0;; offset += nbytes)
	{
		/* If we got a cancel signal during the copy of the file, quit */
		CHECK_FOR_INTERRUPTS();

		/*
		 * We fsync the files later, but during the copy, flush them every so
		 * often to avoid spamming the cache and hopefully get the kernel to
		 * start writing them out before the fsync comes.
		 */
		if (offset - flush_offset >= FLUSH_DISTANCE)
		{
			pg_flush_data(dstfd, flush_offset, offset - flush_offset);
			flush_offset = offset;
		}

		/*
		 * Try to read as much as we fit in the buffer so we can deal with
		 * complete blocks if we need to reencrypt.
		 */
		nbytes = 0;
		while (nbytes < COPY_BUF_SIZE)
		{
			bytesread = read(srcfd, buffer, COPY_BUF_SIZE);
			if (bytesread < 0)
				ereport(ERROR,
						(errcode_for_file_access(),
								errmsg("could not read file \"%s\": %m", fromfile)));
			nbytes += bytesread;
			if (bytesread == 0)
				break;
		}
		if (nbytes == 0)
			break;
		errno = 0;

		/*
		 * If the database is encrypted we need to decrypt the data here
		 * and reencrypt it to adjust the tweak values of blocks.
		 */
		if (fromNode != NULL)
		{
			Assert(toNode != NULL);
			blockNum = ReencryptBlock(buffer, nbytes/BLCKSZ,
									  fromNode, toNode, fromForkNum, toForkNum, blockNum);
		}


		if ((int) write(dstfd, buffer, nbytes) != nbytes)
		{
			/* if write didn't set errno, assume problem is no disk space */
			if (errno == 0)
				errno = ENOSPC;
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write to file \"%s\": %m", tofile)));
		}
	}

	if (offset > flush_offset)
		pg_flush_data(dstfd, flush_offset, offset - flush_offset);

	if (CloseTransientFile(dstfd))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close file \"%s\": %m", tofile)));

	CloseTransientFile(srcfd);

	pfree(buffer);
}

/*
 * Basic parsing of putative relation filenames.
 *
 * This function returns true if the file appears to be in the correct format
 * for a non-temporary relation and false otherwise.
 *
 * NB: If this function returns true, the caller is entitled to assume that
 * *oidchars has been set to the a value no more than OIDCHARS, and thus
 * that a buffer of OIDCHARS+1 characters is sufficient to hold the OID
 * portion of the filename.  This is critical to protect against a possible
 * buffer overrun.
 */
bool
parse_filename_for_nontemp_relation(const char *name, int *oidchars,
									ForkNumber *fork, int *segment)
{
	int			pos;
	int			segstart = 0;

	/* Look for a non-empty string of digits (that isn't too long). */
	for (pos = 0; isdigit((unsigned char) name[pos]); ++pos)
		;
	if (pos == 0 || pos > OIDCHARS)
		return false;
	*oidchars = pos;

	/* Check for a fork name. */
	if (name[pos] != '_')
		*fork = MAIN_FORKNUM;
	else
	{
		int			forkchar;

		forkchar = forkname_chars(&name[pos + 1], fork);
		if (forkchar <= 0)
			return false;
		pos += forkchar + 1;
	}

	/* Check for a segment number. */
	if (name[pos] == '.')
	{
		int			segchar;

		segstart = pos + 1;
		for (segchar = 1; isdigit((unsigned char) name[pos + segchar]); ++segchar)
			;
		if (segchar <= 1)
			return false;
		pos += segchar;
	}

	/* Now we should be at the end. */
	if (name[pos] != '\0')
		return false;

	if (segment != NULL)
	{
		if (segstart == 0)
			*segment = 0;
		else
			*segment = atoi(name + segstart);
	}

	return true;
}
