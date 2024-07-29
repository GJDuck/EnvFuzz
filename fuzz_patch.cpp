/*
 *  ____  ____  _____              
 * |  _ \|  _ \|  ___|   _ ________
 * | |_) | |_) | |_ | | | |_  /_  /
 * |  _ <|  _ <|  _|| |_| |/ / / / 
 * |_| \_\_| \_\_|   \__,_/___/___|
 *
 * Copyright (C) National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

typedef unsigned __int128 HASH;
static bool option_save = false;    // Save-all mode?

static MSG *messages_push_back(MSG *H, MSG *M);
static MSG *messages_free(MSG *H);
static void messages_save(FILE *stream, MSG *H);
static MSG *messages_load(const char *filename, FILE *stream);

struct PATCH                    // Patch representation
{
    MSG *head;                  // Patch messages
    PATCH *next;                // Next patch
    PATCH *prev;                // Prev patch
    const char *filename;       // Patch filename
    bool discard;               // Discard this patch?
    bool disk;                  // Patch is saved to the disk?
    bool cov;                   // Patch had new coverage?

    /*
     * Push a new message onto this patch.
     */
    void push_back(MSG *M)
    {
        head = messages_push_back(head, M);
    }

    /*
     * Merge two patches into the same set (corpus).
     */
    void merge(PATCH *P)
    {
        PATCH *prev_1 = prev, *prev_2 = P->prev;
        prev_1->next = P;
        P->prev      = prev_1;
        prev_2->next = this;
        prev         = prev_2;
    }

    /*
     * Initialize a patch (the "constructor").
     */
    void init(void)
    {
        head = NULL;
        next = prev = this;
        filename = NULL;
        discard = disk = false;
    }

    /*
     * Reset a patch (the "destructor").
     */
    void reset(void)
    {
        head = messages_free(head);
        next->prev  = prev;
        prev->next  = next;
        if (filename != NULL)
        {
            if (!option_save)
                (void)unlink(filename);
            pfree((void *)filename);
            filename = NULL;
        }
        init();
    }

    /*
     * Saves the patch to disk.
     */
    bool save(const char *patchname)
    {
        assert(filename == NULL && !disk);
        int fd = open(patchname, O_WRONLY | O_CREAT | O_EXCL, 0777);
        if (fd < 0)
        {
            if (errno == EEXIST)
                return false;
            error("failed to open file \"%s\" for writing: %s", patchname,
                strerror(errno));
        }
        size_t len = strlen(patchname);
        filename = (char *)pmalloc(len+1);
        memcpy((void *)filename, patchname, len+1);
        FILE *stream = fdopen(fd, "w");
        if (stream == NULL)
            error("failed to open file \"%s\" for writing: %s", filename,
                strerror(errno));
        messages_save(stream, head);
        fclose(stream);
        return true;
    }

    /*
     * Loads the patch from the disk.
     */
    void load(void)
    {
        if (!disk || filename == nullptr)
            return;
        FILE *stream = fopen(filename, "r");
        if (stream == NULL)
            error("failed to open file \"%s\" for reading: %s", filename,
                strerror(errno));
        head = messages_load(filename, stream);
        fclose(stream);
        disk = false;
    }

    /*
     * Unloads the patch from memory.
     */
    void unload(void)
    {
        if (filename == nullptr)
            return;
        head = messages_free(head);
        disk = true;
    }

};

struct CORPUS                   // Set of patches
{
    PATCH head;

    void init(void)
    {
        head.init();
    }

    /*
     * Insert a patch into the corpus.
     */
    void insert(HASH K, PATCH *P)
    {
        assert(P->head != NULL);
        
        // Create the patch filename:
        PRINTER Q;
        Q.format("out/queue/m%u/", P->head->id);
        if (mkdir(Q.str(), 0777) < 0 && errno != EEXIST)
            error("failed to make directory \"%s\": %s", Q.str(),
                strerror(errno));
        Q.format("m%.5u_%.16lx%.16lx.patch", P->head->id,
            (uint64_t)(K >> 64), (uint64_t)K);
        (void)P->save(Q.str());
        head.merge(P);
        P->unload();
    }
};

/*
 * Push back onto messages.
 */
static MSG *messages_push_back(MSG *H, MSG *M)
{
    if (H == NULL)
    {
        M->next = M->prev = M;
        H = M;
    }
    else
    {
        M->next = H;
        M->prev = H->prev;
        H->prev->next = M;
        H->prev       = M;
    }
    return H;
}

/*
 * Free messages.
 */
static MSG *messages_free(MSG *H)
{
    MSG *M = H;
    if (H != NULL)
    {
        do
        {
            MSG *N = M->next;
            pfree(M);
            M = N;
        }
        while (M != H);
    }
    return NULL;
}

/*
 * Write a message to the stream.
 */
static void message_write(FILE *stream, const MSG *M)
{
    fprintf(stream, "PATCH id=#%d len=%zu port=%d src=",
        M->id, M->len, M->port);
    const char *name = port_name(M->port);
    for (size_t i = 0; name[i] != '\0'; i++)
        fputc((isspace(name[i])? '.': name[i]), stream);
    fputs(" data=\n", stream);
    fwrite(M->payload, sizeof(uint8_t), M->len, stream);
    fputc('\n', stream);
}

/*
 * Save messages to the disk.
 */
static void messages_save(FILE *stream, MSG *H)
{
    MSG *M = H;
    if (H != NULL)
    {
        do
        {
            message_write(stream, M);
            M = M->next;
        }
        while (M != H);
    }
}

/*
 * Load messages from the disk.
 */
static MSG *messages_load(const char *filename, FILE *stream)
{
    MSG *H = NULL;
    while (true)
    {
        int id, port;
        size_t len;
        char c, tmp[1001];
        if (fscanf(stream, " PATCH id=#%d len=%zu port=%d src=%1000s data=%c",
                 &id, &len, &port, tmp, &c) != 5 || c != '\n')
            break;
        MSG *M = (MSG *)pmalloc(sizeof(MSG) + len);
        if (M == NULL)
            error("failed to allocate message: %s", strerror(errno));
        M->port     = port;
        M->error    = 0;
        M->outbound = false;
        M->id       = id;
        M->len      = len;
        if (fread(M->payload, sizeof(uint8_t), M->len, stream) != M->len)
            error("failed to read data from \"%s\": %s", filename,
                strerror(errno));
        H = messages_push_back(H, M);
    }
    if (!feof(stream) || ferror(stream))
        error("failed to parse \"%s\"", filename);
    return H;
}

/*
 * Save a single message to the disk.
 */
static void patch_append(const char *filename, const MSG *M)
{
    FILE *stream = fopen(filename, "a");
    if (stream == NULL)
        error("failed to open file \"%s\" for appending: %s", filename,
            strerror(errno));
    message_write(stream, M);
    fclose(stream);
}

/*
 * Save a patch to disk.
 */
static bool patch_save(const char *filename, const PATCH *P)
{
    if (syscall(SYS_access, filename, /*F_OK=*/0) == 0)
        return false;       // Already exists
    FILE *stream = fopen(filename, "w");
    if (stream == NULL)
        error("failed to open file \"%s\" for writing: %s", filename,
            strerror(errno));
    messages_save(stream, P->head);
    fclose(stream);
    return true;
}

/*
 * Load a patch from disk.
 */
static PATCH *patch_load(const char *filename)
{
    FILE *stream = fopen(filename, "r");
    if (stream == NULL)
        error("failed to open file \"%s\" for reading: %s", filename,
            strerror(errno));
    PATCH *P = (PATCH *)xmalloc(sizeof(PATCH));
    P->init();
    P->head = messages_load(filename, stream);
    fclose(stream);
    return P;
}

/*
 * Get the next (patched) message.
 */
static MSG *patch_next(MSG *M, PATCH *P)
{
    if (P == NULL || P->head == NULL || M->id != P->head->id)
        return M;
    M = P->head;
    if (M == M->next)
        P->head = NULL;
    else
    {
        P->head = M->next;
        P->head->prev = M->prev;
    }
    return M;
}

