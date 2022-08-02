/* Fully-inline hash table, used mainly for managing TLS descriptors.
   Copyright (C) 1999-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Alexandre Oliva  <aoliva@redhat.com>

   This file is derived from a 2003's version of libiberty's
   hashtab.c, contributed by Vladimir Makarov (vmakarov@cygnus.com),
   but with most adaptation points and support for deleting elements
   removed.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef INLINE_HASHTAB_H
#define INLINE_HASHTAB_H

//extern void weak_function free (void *ptr);
static void destroy(void *ptr)
{
    if (ptr)
        free(ptr);
}
struct hashtab
{
    /* Table itself. */
    void **entries;

    /* Current size (in entries) of the hash table */
    size_t size;

    /* Current number of elements. */
    size_t n_elements;

    /* Free function for the entries array.  This may vary depending on
     how early the array was allocated.  If it is NULL, then the array
     can't be freed.  */
    void (*free) (void *ptr);
};

inline static struct hashtab *
htab_create (void)
{
    struct hashtab *ht = malloc (sizeof (struct hashtab));

    if (! ht)
        return NULL;
    ht->size = 3;
    ht->entries = malloc (sizeof (void *) * ht->size);
    ht->free = destroy;
    if (! ht->entries)
    {
        if (ht->free)
            ht->free (ht);
        return NULL;
    }

    ht->n_elements = 0;

    memset (ht->entries, 0, sizeof (void *) * ht->size);

    return ht;
}

/* This is only called from _dl_unmap, so it's safe to call
   free().  */
inline static void
htab_delete (struct hashtab *htab)
{
    size_t i = 0;

    for (i = htab->size; i > 0; i--)
        free (htab->entries[i - 1]);

    if (htab->free)
        htab->free (htab->entries);
    free (htab);
}

/* Similar to htab_find_slot, but without several unwanted side effects:
    - Does not call htab->eq_f when it finds an existing entry.
    - Does not change the count of elements/searches/collisions in the
      hash table.
   This function also assumes there are no deleted entries in the table.
   HASH is the hash value for the element to be inserted.  */

inline static void **
find_empty_slot_for_expand (struct hashtab *htab, unsigned int hash)
{
    size_t size = htab->size;
    size_t index = (size_t)hash % size;
    void **slot = htab->entries + index;
    unsigned int hash2 = 0;

    if (! *slot)
        return slot;

    hash2 = (unsigned int)(1 + (size_t)hash % (size - 2));
    for (;;)
    {
        index += hash2;
        if (index >= size)
            index -= size;

        slot = htab->entries + index;
        if (! *slot)
            return slot;
    }
}


inline static unsigned long int
_dl_higher_prime_number (unsigned long int n)
{
    #define UINT32_C(c) c ## U
    /* These are primes that are near, but slightly smaller than, a
        power of two.  */
    static const unsigned int primes[] = {
        UINT32_C (7),
        UINT32_C (13),
        UINT32_C (31),
        UINT32_C (61),
        UINT32_C (127),
        UINT32_C (251),
        UINT32_C (509),
        UINT32_C (1021),
        UINT32_C (2039),
        UINT32_C (4093),
        UINT32_C (8191),
        UINT32_C (16381),
        UINT32_C (32749),
        UINT32_C (65521),
        UINT32_C (131071),
        UINT32_C (262139),
        UINT32_C (524287),
        UINT32_C (1048573),
        UINT32_C (2097143),
        UINT32_C (4194301),
        UINT32_C (8388593),
        UINT32_C (16777213),
        UINT32_C (33554393),
        UINT32_C (67108859),
        UINT32_C (134217689),
        UINT32_C (268435399),
        UINT32_C (536870909),
        UINT32_C (1073741789),
        UINT32_C (2147483647),
        /* 4294967291L */
        UINT32_C (2147483647) + UINT32_C (2147483644)
    };

    const unsigned int *low = &primes[0];
    const unsigned int *high = &primes[sizeof (primes) / sizeof (primes[0])];

    while (low != high)
    {
        const unsigned int *mid = low + (high - low) / 2;
        if (n > *mid)
            low = mid + 1;
        else
            high = mid;
    }

#if 0
    /* If we've run out of primes, abort.  */
    if (n > *low)
    {
        fprintf (stderr, "Cannot find prime bigger than %lu\n", n);
        abort ();
    }
#endif

    return *low;
}

/* The following function changes size of memory allocated for the
   entries and repeatedly inserts the table elements.  The occupancy
   of the table after the call will be about 50%.  Naturally the hash
   table must already exist.  Remember also that the place of the
   table entries is changed.  If memory allocation failures are allowed,
   this function will return zero, indicating that the table could not be
   expanded.  If all goes well, it will return a non-zero value.  */

inline static int
htab_expand (struct hashtab *htab, unsigned int (*hash_fn) (void *))
{
    void **oentries = NULL;
    void **olimit = NULL;
    void **p = NULL;
    void **nentries = NULL;
    size_t nsize = 0;

    oentries = htab->entries;
    olimit = oentries + htab->size;

    /* Resize only when table after removal of unused elements is either
        too full or too empty.  */
    if (htab->n_elements * 2 > htab->size)
        nsize = _dl_higher_prime_number (htab->n_elements * 2);
    else
        nsize = htab->size;

    nentries = calloc (sizeof (void *), nsize);
    if (nentries == NULL)
        return 0;
    htab->entries = nentries;
    htab->size = nsize;

    p = oentries;
    do
    {
        if (*p)
            *find_empty_slot_for_expand (htab, hash_fn (*p)) = *p;
        p++;
    }
    while (p < olimit);

    /* Without recording the free corresponding to the malloc used to
        allocate the table, we couldn't tell whether this was allocated
        by the malloc() built into ld.so or the one in the main
        executable or libc.  Calling free() for something that was
        allocated by the early malloc(), rather than the final run-time
        malloc() could do Very Bad Things (TM).  We will waste memory
        allocated early as long as there's no corresponding free(), but
        this isn't so much memory as to be significant.  */

    if (htab->free)
        htab->free (oentries);

    /* Use the free() corresponding to the malloc() above to free this up.  */
    htab->free = free;

    return 1;
}

/* This function searches for a hash table slot containing an entry
   equal to the given element.  To delete an entry, call this with
   INSERT = 0, then call htab_clear_slot on the slot returned (possibly
   after doing some checks).  To insert an entry, call this with
   INSERT = 1, then write the value you want into the returned slot.
   When inserting an entry, NULL may be returned if memory allocation
   fails.  */

inline static void **
htab_find_slot (struct hashtab *htab, void *ptr, int insert,
    unsigned int (*hash_fn)(void *), int (*eq_fn)(void *, void *))
{
    size_t index = 0;
    unsigned int hash = 0, hash2 = 0;
    size_t size = 0;
    void **entry = NULL;

    if (htab->size * 3 <= htab->n_elements * 4
        && htab_expand (htab, hash_fn) == 0)
        return NULL;

    hash = hash_fn (ptr);

    size = htab->size;
    index = hash % size;

    entry = &htab->entries[index];
    if (!*entry)
        goto empty_entry;
    else if (eq_fn (*entry, ptr))
        return entry;

    hash2 = (unsigned int)(1 + (size_t)hash % (size - 2));
    for (;;)
    {
        index += hash2;
        if (index >= size)
            index -= size;

        entry = &htab->entries[index];
        if (!*entry)
            goto empty_entry;
        else if (eq_fn (*entry, ptr))
            return entry;
    }

empty_entry:
    if (!insert)
        return NULL;

    htab->n_elements++;
    return entry;
}

#endif /* INLINE_HASHTAB_H */
