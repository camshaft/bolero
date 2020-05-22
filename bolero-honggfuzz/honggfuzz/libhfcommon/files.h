/*
 *
 * honggfuzz - file operations
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#ifndef _HF_COMMON_FILES_H_
#define _HF_COMMON_FILES_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

extern ssize_t files_readFileToBufMax(const char* fname, uint8_t* buf, size_t fileMaxSz);
extern bool files_writeBufToFile(const char* fname, const uint8_t* buf, size_t fileSz, int flags);
extern bool files_writeStrToFile(const char* fname, const char* str, int flags);
extern int files_writeBufToTmpFile(const char* dir, const uint8_t* buf, size_t fileSz, int flags);
extern bool files_writeToFd(int fd, const uint8_t* buf, size_t fileSz);
extern bool files_writeStrToFd(int fd, const char* str);
extern ssize_t files_readFromFd(int fd, uint8_t* buf, size_t fileSz);
extern ssize_t files_readFromFdSeek(int fd, uint8_t* buf, size_t fileSz, off_t pos);
extern bool files_writePatternToFd(int fd, off_t size, unsigned char p);

extern bool files_sendToSocketNB(int fd, const uint8_t* buf, size_t fileSz);
extern bool files_sendToSocket(int fd, const uint8_t* buf, size_t fileSz);
extern sa_family_t files_sockFamily(int sock);
extern const char* files_sockAddrToStr(const struct sockaddr* sa, const socklen_t len);

extern bool files_exists(const char* fname);
extern const char* files_basename(const char* path);
extern bool files_resetFile(int fd, size_t sz);

extern uint8_t* files_mapFile(const char* fname, off_t* fileSz, int* fd, bool isWritable);
extern int files_getTmpMapFlags(int flag, bool nocore);
extern int files_createSharedMem(size_t sz, const char* name, bool exportmap);
extern void* files_mapSharedMem(size_t sz, int* fd, const char* name, bool nocore, bool export);

extern size_t files_parseSymbolFilter(const char* inFIle, char*** filterList);

#endif /* ifndef HF_COMMON_FILES */
