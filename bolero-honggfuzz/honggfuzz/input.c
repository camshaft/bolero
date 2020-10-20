/*
 * honggfuzz - file operations
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2020 by Google Inc. All Rights Reserved.
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

#include "input.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "mangle.h"
#include "subproc.h"

void input_setSize(run_t* run, size_t sz) {
    if (run->dynfile->size == sz) {
        return;
    }
    if (sz > run->global->mutate.maxInputSz) {
        PLOG_F("Too large size requested: %zu > maxSize: %zu", sz, run->global->mutate.maxInputSz);
    }
    /* ftruncate of a mmaped file fails under CygWin, it's also painfully slow under MacOS X */
#if !defined(__CYGWIN__) && !defined(_HF_ARCH_DARWIN)
    if (TEMP_FAILURE_RETRY(ftruncate(run->dynfile->fd, sz)) == -1) {
        PLOG_W("ftruncate(run->dynfile->fd=%d, sz=%zu)", run->dynfile->fd, sz);
    }
#endif /* !defined(__CYGWIN__) && !defined(_HF_ARCH_DARWIN) */
    run->dynfile->size = sz;
}

bool input_getDirStatsAndRewind(honggfuzz_t* hfuzz) {
    rewinddir(hfuzz->io.inputDirPtr);

    size_t fileCnt = 0U;
    for (;;) {
        errno                = 0;
        struct dirent* entry = readdir(hfuzz->io.inputDirPtr);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir('%s')", hfuzz->io.inputDir);
            return false;
        }
        if (entry == NULL) {
            break;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", hfuzz->io.inputDir, entry->d_name);

        LOG_D("Analyzing file '%s'", path);

        struct stat st;
        if (stat(path, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", path);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", path);
            continue;
        }
        if (hfuzz->io.maxFileSz && st.st_size > (off_t)hfuzz->io.maxFileSz) {
            LOG_D("File '%s' is bigger than maximal defined file size (-F): %" PRIu64 " > %zu",
                path, (uint64_t)st.st_size, hfuzz->io.maxFileSz);
        }
        if ((size_t)st.st_size > hfuzz->mutate.maxInputSz) {
            hfuzz->mutate.maxInputSz = st.st_size;
        }
        fileCnt++;
    }

    ATOMIC_SET(hfuzz->io.fileCnt, fileCnt);
    if (hfuzz->io.maxFileSz) {
        hfuzz->mutate.maxInputSz = hfuzz->io.maxFileSz;
    } else if (hfuzz->mutate.maxInputSz < _HF_INPUT_DEFAULT_SIZE) {
        hfuzz->mutate.maxInputSz = _HF_INPUT_DEFAULT_SIZE;
    } else if (hfuzz->mutate.maxInputSz > _HF_INPUT_MAX_SIZE) {
        hfuzz->mutate.maxInputSz = _HF_INPUT_MAX_SIZE;
    }

    if (hfuzz->io.fileCnt == 0U) {
        LOG_W("No usable files in the input directory '%s'", hfuzz->io.inputDir);
    }

    LOG_D("Analyzed '%s' directory: maxInputSz:%zu, number of usable files:%zu", hfuzz->io.inputDir,
        hfuzz->mutate.maxInputSz, hfuzz->io.fileCnt);

    rewinddir(hfuzz->io.inputDirPtr);

    return true;
}

bool input_getNext(run_t* run, char fname[PATH_MAX], bool rewind) {
    MX_SCOPED_LOCK(&run->global->mutex.input);

    if (run->global->io.fileCnt == 0U) {
        LOG_W("No useful files in the input directory");
        return false;
    }

    for (;;) {
        errno                = 0;
        struct dirent* entry = readdir(run->global->io.inputDirPtr);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir_r('%s')", run->global->io.inputDir);
            return false;
        }
        if (entry == NULL && !rewind) {
            return false;
        }
        if (entry == NULL && rewind) {
            if (!input_getDirStatsAndRewind(run->global)) {
                LOG_E("input_getDirStatsAndRewind('%s')", run->global->io.inputDir);
                return false;
            }
            continue;
        }
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "%s/%s", run->global->io.inputDir, entry->d_name);
        struct stat st;
        if (stat(path, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", path);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", path);
            continue;
        }

        snprintf(fname, PATH_MAX, "%s", entry->d_name);
        return true;
    }
}

bool input_init(honggfuzz_t* hfuzz) {
    hfuzz->io.fileCnt = 0U;

    if (!hfuzz->io.inputDir) {
        LOG_W("No input file/dir specified");
        return false;
    }

    int dir_fd = TEMP_FAILURE_RETRY(open(hfuzz->io.inputDir, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (dir_fd == -1) {
        PLOG_W("open('%s', O_DIRECTORY|O_RDONLY|O_CLOEXEC)", hfuzz->io.inputDir);
        return false;
    }
    if ((hfuzz->io.inputDirPtr = fdopendir(dir_fd)) == NULL) {
        PLOG_W("fdopendir(dir='%s', fd=%d)", hfuzz->io.inputDir, dir_fd);
        close(dir_fd);
        return false;
    }
    if (!input_getDirStatsAndRewind(hfuzz)) {
        hfuzz->io.fileCnt = 0U;
        LOG_W("input_getDirStatsAndRewind('%s')", hfuzz->io.inputDir);
        return false;
    }

    return true;
}

bool input_parseDictionary(honggfuzz_t* hfuzz) {
    LOG_I("Parsing dictionary file '%s'", hfuzz->mutate.dictionaryFile);

    FILE* fDict = fopen(hfuzz->mutate.dictionaryFile, "rb");
    if (fDict == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->mutate.dictionaryFile);
        return false;
    }
    defer {
        fclose(fDict);
    };

    char*  lineptr = NULL;
    size_t n       = 0;
    defer {
        free(lineptr);
    };
    for (;;) {
        ssize_t len = getdelim(&lineptr, &n, '\n', fDict);
        if (len == -1) {
            break;
        }
        if (hfuzz->mutate.dictionaryCnt == ARRAYSIZE(hfuzz->mutate.dictionary)) {
            LOG_W("Maximum number of dictionary entries '%zu' alread loaded. Skipping the rest",
                ARRAYSIZE(hfuzz->mutate.dictionary));
            break;
        }
        if (len > 1 && lineptr[len - 1] == '\n') {
            lineptr[len - 1] = '\0';
            len--;
        }
        if (lineptr[0] == '#') {
            continue;
        }
        if (lineptr[0] == '\n') {
            continue;
        }
        if (lineptr[0] == '\0') {
            continue;
        }

        const char* start = strchr(lineptr, '"');
        char*       end   = strrchr(lineptr, '"');
        if (!start || !end) {
            LOG_W("Malformed dictionary line '%s', skipping", lineptr);
            continue;
        }
        if ((uintptr_t)start == (uintptr_t)end) {
            LOG_W("Malformed dictionary line '%s', skipping", lineptr);
            continue;
        }
        *end = '\0';

        char bufv[1025] = {};
        if (sscanf(&start[1], "%1024c", bufv) != 1) {
            LOG_W("Malformed dictionary line '%s', skipping", lineptr);
            continue;
        }

        LOG_D("Parsing dictionary word: '%s'", bufv);

        len              = util_decodeCString(bufv);
        size_t dictEntry = ATOMIC_POST_INC(hfuzz->mutate.dictionaryCnt);
        len              = HF_MIN((size_t)len, sizeof(hfuzz->mutate.dictionary[dictEntry].val));
        memcpy(hfuzz->mutate.dictionary[dictEntry].val, bufv, len);
        hfuzz->mutate.dictionary[dictEntry].len = len;

        LOG_D("Dictionary: loaded word: '%s' (len=%zd)", bufv, len);
    }
    LOG_I("Loaded %zu words from the dictionary '%s'", hfuzz->mutate.dictionaryCnt,
        hfuzz->mutate.dictionaryFile);
    return true;
}

bool input_parseBlacklist(honggfuzz_t* hfuzz) {
    FILE* fBl = fopen(hfuzz->feedback.blacklistFile, "rb");
    if (fBl == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->feedback.blacklistFile);
        return false;
    }
    defer {
        fclose(fBl);
    };

    char* lineptr = NULL;
    /* lineptr can be NULL, but it's fine for free() */
    defer {
        free(lineptr);
    };
    size_t n = 0;
    for (;;) {
        if (getline(&lineptr, &n, fBl) == -1) {
            break;
        }

        if ((hfuzz->feedback.blacklist = util_Realloc(hfuzz->feedback.blacklist,
                 (hfuzz->feedback.blacklistCnt + 1) * sizeof(hfuzz->feedback.blacklist[0]))) ==
            NULL) {
            PLOG_W("realloc failed (sz=%zu)",
                (hfuzz->feedback.blacklistCnt + 1) * sizeof(hfuzz->feedback.blacklist[0]));
            return false;
        }

        hfuzz->feedback.blacklist[hfuzz->feedback.blacklistCnt] = strtoull(lineptr, 0, 16);
        LOG_D("Blacklist: loaded %'" PRIu64 "'",
            hfuzz->feedback.blacklist[hfuzz->feedback.blacklistCnt]);

        /* Verify entries are sorted so we can use interpolation search */
        if (hfuzz->feedback.blacklistCnt >= 1) {
            if (hfuzz->feedback.blacklist[hfuzz->feedback.blacklistCnt - 1] >
                hfuzz->feedback.blacklist[hfuzz->feedback.blacklistCnt]) {
                LOG_F("Blacklist file not sorted. Use 'tools/createStackBlacklist.sh' to sort "
                      "records");
                return false;
            }
        }
        hfuzz->feedback.blacklistCnt += 1;
    }

    if (hfuzz->feedback.blacklistCnt > 0) {
        LOG_I("Loaded %zu stack hash(es) from the blacklist file", hfuzz->feedback.blacklistCnt);
    } else {
        LOG_F("Empty stack hashes blacklist file '%s'", hfuzz->feedback.blacklistFile);
    }
    return true;
}

static void input_generateFileName(dynfile_t* dynfile, const char* dir, char fname[PATH_MAX]) {
    uint64_t crc64f = util_CRC64(dynfile->data, dynfile->size);
    uint64_t crc64r = util_CRC64Rev(dynfile->data, dynfile->size);
    if (dir) {
        snprintf(fname, PATH_MAX, "%s/%016" PRIx64 "%016" PRIx64 ".%08" PRIx32 ".honggfuzz.cov",
            dir, crc64f, crc64r, (uint32_t)dynfile->size);
    } else {
        snprintf(fname, PATH_MAX, "%016" PRIx64 "%016" PRIx64 ".%08" PRIx32 ".honggfuzz.cov",
            crc64f, crc64r, (uint32_t)dynfile->size);
    }
}

bool input_writeCovFile(const char* dir, dynfile_t* dynfile) {
    char fname[PATH_MAX];
    input_generateFileName(dynfile, dir, fname);

    if (files_exists(fname)) {
        LOG_D("File '%s' already exists in the output corpus directory '%s'", fname, dir);
        return true;
    }

    LOG_D("Adding file '%s' to the corpus directory '%s'", fname, dir);

    if (!files_writeBufToFile(
            fname, dynfile->data, dynfile->size, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC)) {
        LOG_W("Couldn't write buffer to file '%s' (sz=%zu)", fname, dynfile->size);
        return false;
    }

    return true;
}

/* true if item1 is bigger than item2 */
static bool input_cmpCov(dynfile_t* item1, dynfile_t* item2) {
    for (size_t j = 0; j < ARRAYSIZE(item1->cov); j++) {
        if (item1->cov[j] > item2->cov[j]) {
            return true;
        }
        if (item1->cov[j] < item2->cov[j]) {
            return false;
        }
    }
    /* Both are equal */
    return false;
}

#define TAILQ_FOREACH_HF(var, head, field)                                                         \
    for ((var) = TAILQ_FIRST((head)); (var); (var) = TAILQ_NEXT((var), field))

void input_addDynamicInput(run_t* run) {
    ATOMIC_SET(run->global->timing.lastCovUpdate, time(NULL));

    dynfile_t* dynfile     = (dynfile_t*)util_Calloc(sizeof(dynfile_t));
    dynfile->size          = run->dynfile->size;
    dynfile->timeExecUSecs = util_timeNowUSecs() - run->timeStartedUSecs;
    dynfile->data          = (uint8_t*)util_AllocCopy(run->dynfile->data, run->dynfile->size);
    dynfile->src           = run->dynfile->src;
    memcpy(dynfile->cov, run->dynfile->cov, sizeof(dynfile->cov));
    if (run->dynfile->src) {
        ATOMIC_POST_INC(run->dynfile->src->refs);
    }
    input_generateFileName(dynfile, NULL, dynfile->path);

    MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);

    dynfile->idx = ATOMIC_PRE_INC(run->global->io.dynfileqCnt);

    run->global->feedback.maxCov[0] = HF_MAX(run->global->feedback.maxCov[0], dynfile->cov[0]);
    run->global->feedback.maxCov[1] = HF_MAX(run->global->feedback.maxCov[1], dynfile->cov[1]);
    run->global->feedback.maxCov[2] = HF_MAX(run->global->feedback.maxCov[2], dynfile->cov[2]);
    run->global->feedback.maxCov[3] = HF_MAX(run->global->feedback.maxCov[3], dynfile->cov[3]);

    run->global->io.dynfileqMaxSz = HF_MAX(run->global->io.dynfileqMaxSz, dynfile->size);

    /* Sort it by coverage - put better coverage earlier in the list */
    dynfile_t* iter = NULL;
    TAILQ_FOREACH_HF (iter, &run->global->io.dynfileq, pointers) {
        if (input_cmpCov(dynfile, iter)) {
            TAILQ_INSERT_BEFORE(iter, dynfile, pointers);
            break;
        }
    }
    if (iter == NULL) {
        TAILQ_INSERT_TAIL(&run->global->io.dynfileq, dynfile, pointers);
    }

    if (run->global->socketFuzzer.enabled) {
        /* Don't add coverage data to files in socketFuzzer mode */
        return;
    }

    const char* outDir =
        run->global->io.outputDir ? run->global->io.outputDir : run->global->io.inputDir;
    if (!input_writeCovFile(outDir, dynfile)) {
        LOG_E("Couldn't save the coverage data to '%s'", run->global->io.outputDir);
    }

    /* No need to add files to the new coverage dir, if it's not the main phase */
    if (fuzz_getState(run->global) != _HF_STATE_DYNAMIC_MAIN) {
        return;
    }

    ATOMIC_POST_INC(run->global->io.newUnitsAdded);

    if (run->global->io.covDirNew && !input_writeCovFile(run->global->io.covDirNew, dynfile)) {
        LOG_E("Couldn't save the new coverage data to '%s'", run->global->io.covDirNew);
    }
}

bool input_inDynamicCorpus(run_t* run, const char* fname) {
    MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);

    dynfile_t* iter = NULL;
    TAILQ_FOREACH_HF (iter, &run->global->io.dynfileq, pointers) {
        if (strncmp(iter->path, fname, PATH_MAX) == 0) {
            return true;
        }
    }
    return false;
}

static inline int input_speedFactor(run_t* run, dynfile_t* dynfile) {
    /* Slower the input, lower the chance of it being tested */
    uint64_t avg_usecs_per_input =
        ((uint64_t)(time(NULL) - run->global->timing.timeStart) * 1000000);
    avg_usecs_per_input /= ATOMIC_GET(run->global->cnts.mutationsCnt);
    avg_usecs_per_input /= run->global->threads.threadsMax;

    /* Cap both vals to 1us-1s */
    avg_usecs_per_input   = HF_CAP(avg_usecs_per_input, 1U, 1000000U);
    uint64_t sample_usecs = HF_CAP(dynfile->timeExecUSecs, 1U, 1000000U);

    if (sample_usecs >= avg_usecs_per_input) {
        return (int)(sample_usecs / avg_usecs_per_input);
    } else {
        return -(int)(avg_usecs_per_input / sample_usecs);
    }
}

static inline int input_skipFactor(run_t* run, dynfile_t* dynfile, int* speed_factor) {
    int penalty = 0;

    {
        *speed_factor = HF_CAP(input_speedFactor(run, dynfile) / 2, -15, 15);
        penalty += *speed_factor;
    }

    {
        /* Inputs with lower total coverage -> lower chance of being tested */
        static const int scaleMap[200] = {
            [95 ... 199] = -15,
            [90 ... 94]  = -7,
            [80 ... 89]  = -3,
            [60 ... 79]  = -1,
            [50 ... 59]  = 0,
            [30 ... 49]  = 5,
            [11 ... 29]  = 10,
            [0 ... 10]   = 15,
        };

        uint64_t maxCov0 = ATOMIC_GET(run->global->feedback.maxCov[0]);
        if (maxCov0) {
            const unsigned percentile = (dynfile->cov[0] * 100) / maxCov0;
            penalty += scaleMap[percentile];
        }
    }

    {
        /* Older inputs -> lower chance of being tested */
        static const int scaleMap[200] = {
            [100 ... 199] = -10,
            [95 ... 99]   = -5,
            [91 ... 94]   = -1,
            [81 ... 90]   = 0,
            [71 ... 80]   = 1,
            [41 ... 70]   = 2,
            [0 ... 40]    = 3,
        };

        const unsigned percentile = (dynfile->idx * 100) / run->global->io.dynfileqCnt;
        penalty += scaleMap[percentile];
    }

    {
        /* If the input wasn't source of other inputs so far, make it less likely to be tested */
        penalty += HF_CAP((1 - (int)dynfile->refs) * 3, -30, 5);
    }

    {
        /* Add penalty for the input being too big - 0 is for 1kB inputs */
        if (dynfile->size > 0) {
            penalty += HF_CAP(((int)util_Log2(dynfile->size) - 10), -5, 5);
        }
    }

    return penalty;
}

bool input_prepareDynamicInput(run_t* run, bool needs_mangle) {
    if (ATOMIC_GET(run->global->io.dynfileqCnt) == 0) {
        LOG_F("The dynamic file corpus is empty. This shouldn't happen");
    }

    int speed_factor = 0;
    for (;;) {
        MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);

        if (run->global->io.dynfileqCurrent == NULL) {
            run->global->io.dynfileqCurrent = TAILQ_FIRST(&run->global->io.dynfileq);
        }

        if (run->triesLeft) {
            run->triesLeft--;
            break;
        }

        run->current                    = run->global->io.dynfileqCurrent;
        run->global->io.dynfileqCurrent = TAILQ_NEXT(run->global->io.dynfileqCurrent, pointers);

        int skip_factor = input_skipFactor(run, run->current, &speed_factor);
        if (skip_factor <= 0) {
            run->triesLeft = -(skip_factor);
            break;
        }

        if ((util_rnd64() % skip_factor) == 0) {
            break;
        }
    }

    input_setSize(run, run->current->size);
    run->dynfile->idx           = run->current->idx;
    run->dynfile->timeExecUSecs = run->current->timeExecUSecs;
    run->dynfile->src           = run->current;
    run->dynfile->refs          = 0;
    memcpy(run->dynfile->cov, run->current->cov, sizeof(run->dynfile->cov));
    snprintf(run->dynfile->path, sizeof(run->dynfile->path), "%s", run->current->path);
    memcpy(run->dynfile->data, run->current->data, run->current->size);

    if (needs_mangle) {
        mangle_mangleContent(run, speed_factor);
    }

    return true;
}

size_t input_getRandomInputAsBuf(run_t* run, const uint8_t** buf) {
    if (ATOMIC_GET(run->global->io.dynfileqCnt) == 0) {
        LOG_E("The dynamic input queue shouldn't be empty");
        *buf = NULL;
        return 0;
    }

    dynfile_t* current = NULL;
    {
        MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);

        if (run->global->io.dynfileq2Current == NULL) {
            run->global->io.dynfileq2Current = TAILQ_FIRST(&run->global->io.dynfileq);
        }

        current                          = run->global->io.dynfileq2Current;
        run->global->io.dynfileq2Current = TAILQ_NEXT(run->global->io.dynfileq2Current, pointers);
    }

    *buf = current->data;
    return current->size;
}

static bool input_shouldReadNewFile(run_t* run) {
    if (fuzz_getState(run->global) != _HF_STATE_DYNAMIC_DRY_RUN) {
        input_setSize(run, run->global->mutate.maxInputSz);
        return true;
    }

    if (!run->staticFileTryMore) {
        run->staticFileTryMore = true;
        /* Start with 4 bytes, increase the size in following iterations */
        input_setSize(run, HF_MIN(4U, run->global->mutate.maxInputSz));
        return true;
    }

    /* Increase size of the current file by a factor of 2, and return it instead of a new file */
    size_t newsz = run->dynfile->size * 2;
    if (newsz >= run->global->mutate.maxInputSz) {
        /* That's the largest size for this specific file that will be ever used */
        newsz                  = run->global->mutate.maxInputSz;
        run->staticFileTryMore = false;
    }

    input_setSize(run, newsz);
    return false;
}

bool input_prepareStaticFile(run_t* run, bool rewind, bool needs_mangle) {
    if (input_shouldReadNewFile(run)) {
        for (;;) {
            if (!input_getNext(run, run->dynfile->path, /* rewind= */ rewind)) {
                return false;
            }
            if (!needs_mangle || !input_inDynamicCorpus(run, run->dynfile->path)) {
                LOG_D("Skipping '%s' as it's already in the dynamic corpus", run->dynfile->path);
                break;
            }
        }
        run->global->io.testedFileCnt++;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", run->global->io.inputDir, run->dynfile->path);

    ssize_t fileSz = files_readFileToBufMax(path, run->dynfile->data, run->dynfile->size);
    if (fileSz < 0) {
        LOG_E("Couldn't read contents of '%s'", path);
        return false;
    }

    if (run->staticFileTryMore && ((size_t)fileSz < run->dynfile->size)) {
        /* The file is smaller than the requested size, no need to re-read it anymore */
        run->staticFileTryMore = false;
    }

    input_setSize(run, fileSz);
    memset(run->dynfile->cov, '\0', sizeof(run->dynfile->cov));
    run->dynfile->idx  = 0;
    run->dynfile->src  = NULL;
    run->dynfile->refs = 0;

    if (needs_mangle) {
        mangle_mangleContent(run, /* slow_factor= */ 0);
    }

    return true;
}

bool input_removeStaticFile(const char* dir, const char* name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (unlink(path) == -1 && errno != EEXIST) {
        PLOG_E("unlink('%s') failed", path);
        return false;
    }
    return true;
}

bool input_prepareExternalFile(run_t* run) {
    snprintf(run->dynfile->path, sizeof(run->dynfile->path), "[EXTERNAL]");

    int fd = files_writeBufToTmpFile(run->global->io.workDir, (const uint8_t*)"", 0, 0);
    if (fd == -1) {
        LOG_E("Couldn't write input file to a temporary buffer");
        return false;
    }
    defer {
        close(fd);
    };

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/dev/fd/%d", fd);

    const char* const argv[] = {run->global->exe.externalCommand, fname, NULL};
    if (subproc_System(run, argv) != 0) {
        LOG_E("Subprocess '%s' returned abnormally", run->global->exe.externalCommand);
        return false;
    }
    LOG_D("Subporcess '%s' finished with success", run->global->exe.externalCommand);

    input_setSize(run, run->global->mutate.maxInputSz);
    ssize_t sz = files_readFromFdSeek(fd, run->dynfile->data, run->global->mutate.maxInputSz, 0);
    if (sz == -1) {
        LOG_E("Couldn't read file from fd=%d", fd);
        return false;
    }

    input_setSize(run, (size_t)sz);
    return true;
}

bool input_postProcessFile(run_t* run, const char* cmd) {
    int fd =
        files_writeBufToTmpFile(run->global->io.workDir, run->dynfile->data, run->dynfile->size, 0);
    if (fd == -1) {
        LOG_E("Couldn't write input file to a temporary buffer");
        return false;
    }
    defer {
        close(fd);
    };

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/dev/fd/%d", fd);

    const char* const argv[] = {cmd, fname, NULL};
    if (subproc_System(run, argv) != 0) {
        LOG_E("Subprocess '%s' returned abnormally", cmd);
        return false;
    }
    LOG_D("Subporcess '%s' finished with success", cmd);

    input_setSize(run, run->global->mutate.maxInputSz);
    ssize_t sz = files_readFromFdSeek(fd, run->dynfile->data, run->global->mutate.maxInputSz, 0);
    if (sz == -1) {
        LOG_E("Couldn't read file from fd=%d", fd);
        return false;
    }

    input_setSize(run, (size_t)sz);

    return true;
}
