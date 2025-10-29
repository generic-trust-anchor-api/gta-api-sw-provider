/* SPDX-License-Identifier: Apache-2.0 */
/**********************************************************************
 * Copyright (c) 2024, Siemens AG
 **********************************************************************/

#include "myio_filestream.h"

#include <gta_api/gta_api.h>
#include <gta_api/util/gta_memset.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * myio_ifilestream reference implementation
 */

GTA_DEFINE_FUNCTION(bool, myio_close_ifilestream, (myio_ifilestream_t * istream, gta_errinfo_t * p_errinfo))
{
    fclose(istream->file);
    gta_memset(istream, sizeof(myio_ifilestream_t), 0, sizeof(myio_ifilestream_t));
    return true;
}

GTA_DEFINE_FUNCTION(
    size_t,
    myio_ifilestream_read,
    (myio_ifilestream_t * istream, char * data, size_t len, gta_errinfo_t * p_errinfo))
{
    return fread(data, sizeof(char), len, istream->file);
}

GTA_DEFINE_FUNCTION(bool, myio_ifilestream_eof, (myio_ifilestream_t * istream, gta_errinfo_t * p_errinfo))
{
    return feof(istream->file) != 0 ? true : false;
}

GTA_DEFINE_FUNCTION(
    bool,
    myio_open_ifilestream,
    (myio_ifilestream_t * istream, const char * filename, gta_errinfo_t * p_errinfo))
{
    bool ret = false;
    FILE * file = NULL;

#ifdef WINDOWS
    errno_t err = -1;
    err = fopen_s(&file, filename, "rb");
    if (err == 0)
#else
    if (NULL != (file = fopen(filename, "rb")))
#endif
    {
        istream->read = (gtaio_stream_read_t)myio_ifilestream_read;
        istream->eof = (gtaio_stream_eof_t)myio_ifilestream_eof;
        istream->file = file;
        ret = true;
    } else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

/*
 * myio_ofilestream reference implementation
 */

GTA_DEFINE_FUNCTION(bool, myio_close_ofilestream, (myio_ofilestream_t * ostream, gta_errinfo_t * p_errinfo))
{
    fclose(ostream->file);
    gta_memset(ostream, sizeof(myio_ofilestream_t), 0, sizeof(myio_ofilestream_t));
    return true;
}

GTA_DEFINE_FUNCTION(
    size_t,
    myio_ofilestream_write,
    (myio_ofilestream_t * ostream, char * data, size_t len, gta_errinfo_t * p_errinfo))
{
    return fwrite(data, sizeof(char), len, ostream->file);
}

GTA_DEFINE_FUNCTION(
    bool,
    myio_ofilestream_finish,
    (myio_ofilestream_t * ostream, gta_errinfo_t errinfo, gta_errinfo_t * p_errinfo))
{
    /* todo: what to do with errinfo? */
    return true;
}

GTA_DEFINE_FUNCTION(
    bool,
    myio_open_ofilestream,
    (myio_ofilestream_t * ostream, const char * filename, gta_errinfo_t * p_errinfo))
{
    bool ret = false;
    FILE * file = NULL;

#ifdef WINDOWS
    errno_t err = -1;
    err = fopen_s(&file, filename, "wb");
    if (err == 0)
#else
    if (NULL != (file = fopen(filename, "wb")))
#endif
    {
        ostream->write = (gtaio_stream_write_t)myio_ofilestream_write;
        ostream->finish = (gtaio_stream_finish_t)myio_ofilestream_finish;
        ostream->file = file;
        ret = true;
    } else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

/*** end of file ***/
