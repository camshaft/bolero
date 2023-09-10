/*
 *
 * honggfuzz - namespace related utils
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2017 by Google Inc. All Rights Reserved.
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

#ifndef _HF_NS_H_
#define _HF_NS_H_

#if defined(_HF_ARCH_LINUX)

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

bool nsSetup(uid_t origuid, gid_t origgid);
bool nsEnter(uintptr_t cloneFlags);
bool nsIfaceUp(const char* ifacename);
bool nsMountTmpfs(const char* dst, const char* opts);

#endif /* defined(_HF_ARCH_LINUX) */

#endif
