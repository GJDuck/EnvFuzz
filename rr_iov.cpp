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

/*
 * IOV iterator.
 */
struct iov_itr_s
{
    const struct iovec *iov;
    size_t iovcnt;
    size_t i, j;
};
typedef struct iov_itr_s *iov_itr_t;
#define IOV_ITR(iov, iovcnt)    {(iov), (iovcnt), 0, 0}
static void iov_itr_normalize(iov_itr_t i)
{
    while (i->i < i->iovcnt && i->j >= i->iov[i->i].iov_len)
    {
        i->i++;
        i->j = 0;
    }
}
static bool iov_itr_end(iov_itr_t i)
{
    iov_itr_normalize(i);
    return (i->i >= i->iovcnt);
}
static void iov_itr_reset(iov_itr_t i)
{
    i->i = i->j = 0;
}
static uint8_t *iov_itr_ptr(iov_itr_t i)
{
    return (iov_itr_end(i)? NULL:
                            (uint8_t *)i->iov[i->i].iov_base+i->j);
}
static uint8_t iov_itr_get(iov_itr_t i)
{
    return (iov_itr_end(i)? 0x00:
                            *((const uint8_t *)i->iov[i->i].iov_base+i->j));
}
static char iov_itr_getc(iov_itr_t i)
{
    return (char)iov_itr_get(i);
}
static void iov_itr_inc(iov_itr_t i)
{
    if (iov_itr_end(i))
        return;
    i->j++;
}

/*
 * Get the length of an IOV.
 */
static size_t iov_len(const struct iovec *iov, size_t iovcnt)
{
    struct iov_itr_s i0 = IOV_ITR(iov, iovcnt);
    iov_itr_t i = &i0;
    size_t len = 0;
    while (!iov_itr_end(i))
    {
        len++;
        iov_itr_inc(i);
    }
    return len;
}

/*
 * Test if IOVs are equal.
 */
static bool iov_equal(const struct iovec *iov1, size_t iovcnt1,
    const struct iovec *iov2, size_t iovcnt2, size_t max)
{
    struct iov_itr_s i0 = IOV_ITR(iov1, iovcnt1);
    struct iov_itr_s j0 = IOV_ITR(iov2, iovcnt2);
    iov_itr_t i = &i0, j = &j0;
    bool same = true;
    while (same && max > 0 && !iov_itr_end(i) && !iov_itr_end(j))
    {
        same = (iov_itr_get(i) == iov_itr_get(j));
        iov_itr_inc(i);
        iov_itr_inc(j);
        max--;
    }
    if (max == 0)
        return true;
    same = same && iov_itr_end(i) && iov_itr_end(j);
    return same;
}

/*
 * Copy IOVs.
 */
static size_t iov_copy(const struct iovec *iov1, size_t iovcnt1,
    const struct iovec *iov2, size_t iovcnt2, size_t len)
{
    struct iov_itr_s i0 = IOV_ITR(iov1, iovcnt1);
    struct iov_itr_s j0 = IOV_ITR(iov2, iovcnt2);
    iov_itr_t i = &i0, j = &j0;
    size_t k = 0;
    for (k = 0; k < len && !iov_itr_end(i) && !iov_itr_end(j); k++)
    {
        *iov_itr_ptr(i) = iov_itr_get(j);
        iov_itr_inc(i);
        iov_itr_inc(j);
    }
    return k;
}
static size_t iov_copy(uint8_t *buf, size_t size,
    const struct iovec *iov, size_t iovcnt, size_t len)
{
    struct iovec iov2 = {buf, size};
    return iov_copy(&iov2, 1, iov, iovcnt, len);
}

/*
 * Flatten an IOV into a single buffer.
 */
static uint8_t *iov_flatten(const struct iovec *iov, size_t iovcnt,
    size_t max)
{
    if (iovcnt == 0 || max == 0)
        return NULL;
    size_t len = iov_len(iov, iovcnt);
    len = MIN(len, max);
    uint8_t *buf = (uint8_t *)xmalloc(len);
    struct iovec iov2 = {buf, len};
    iov_copy(&iov2, 1, iov, iovcnt, len);
    return buf;
}

