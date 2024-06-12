/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#ifndef GTA_FILESTREAM_H
#define GTA_FILESTREAM_H

#if defined (_MSC_VER) && (_MSC_VER > 1000)
/* microsoft */
/* Specifies that the file will be included (opened) only
   once by the compiler in a build. This can reduce build
   times as the compiler will not open and read the file
   after the first #include of the module. */
#pragma once
#endif

#if defined(__cplusplus)
   /* *INDENT-OFF* */
extern "C"
{
    /* *INDENT-ON* */
#endif

/*---------------------------------------------------------------------*/

#include <stdio.h>

#include <gta_api/gta_api.h>

/*
 * myio_ifilestream reference implementation for gta_istream interface
 */

typedef struct myio_ifilestream {
    /* public interface as defined for gta_istream */
    gtaio_stream_read_t read;
    gtaio_stream_eof_t eof;
    void * p_reserved2;

    /* private implementation details */
    FILE * file;
} myio_ifilestream_t;

GTA_DECLARE_FUNCTION(bool, myio_close_ifilestream,
(
    myio_ifilestream_t * istream,
    gta_errinfo_t * p_errinfo
));

GTA_DECLARE_FUNCTION(size_t, myio_ifilestream_read,
(
    myio_ifilestream_t * istream,
    char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
));

GTA_DECLARE_FUNCTION(bool, myio_ifilestream_eof,
(
    myio_ifilestream_t * istream,
    gta_errinfo_t * p_errinfo
));

GTA_DECLARE_FUNCTION(bool, myio_open_ifilestream,
(
    myio_ifilestream_t * istream,
    const char * filename,
    gta_errinfo_t * p_errinfo
));

/*
 * myio_ofilestream reference implementation for gta_istream interface
 */

typedef struct myio_ofilestream {
    /* public interface as defined for gta_ostream */
    void * p_reserved0;
    void * p_reserved1;
    gtaio_stream_write_t write;
    gtaio_stream_finish_t finish;

    /* private implementation details */
    FILE * file;
} myio_ofilestream_t;

GTA_DECLARE_FUNCTION(bool, myio_close_ofilestream,
(
    myio_ofilestream_t * ostream,
    gta_errinfo_t * p_errinfo
));

GTA_DECLARE_FUNCTION(size_t, myio_ofilestream_write,
(
    myio_ofilestream_t * ostream,
    char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
));

GTA_DECLARE_FUNCTION(bool, myio_ofilestream_finish,
(
    myio_ofilestream_t * ostream,
    gta_errinfo_t errinfo,
    gta_errinfo_t * p_errinfo
));

GTA_DECLARE_FUNCTION(bool, myio_open_ofilestream,
(
    myio_ofilestream_t * ostream,
    const char * filename,
    gta_errinfo_t * p_errinfo
));


/*---------------------------------------------------------------------*/

#if defined(__cplusplus)
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /* GTA_BUFSTREAM_H */

/*** end of file ***/



