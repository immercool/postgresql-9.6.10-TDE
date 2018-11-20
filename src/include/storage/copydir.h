/*-------------------------------------------------------------------------
 *
 * copydir.h
 *	  Copy a directory.
 *
 * Portions Copyright (c) 1996-2016, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/copydir.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef COPYDIR_H
#define COPYDIR_H


#include "storage/relfilenode.h"

extern void copydir(char *fromdir, char *todir, RelFileNode *fromNode, RelFileNode *toNode);
extern void copy_file(char *fromfile, char *tofile, RelFileNode *fromNode, RelFileNode *toNode, ForkNumber fromForkNum, ForkNumber toForkNum, int segment);
extern bool parse_filename_for_nontemp_relation(const char *name,
                                                int *oidchars, ForkNumber *fork, int *segment);


#endif   /* COPYDIR_H */
