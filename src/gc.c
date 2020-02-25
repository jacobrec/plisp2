#include <plisp/gc.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <string.h>

#define MAX_ALLOC_PAGE_SIZE 64
#define BLOCK_BITS (sizeof(size_t)*8)
#define TYPE_BIT_WIDTH (sizeof(size_t)*8)

struct obj_allocs {
    size_t allocated[MAX_ALLOC_PAGE_SIZE/BLOCK_BITS];
    size_t types[2*MAX_ALLOC_PAGE_SIZE/BLOCK_BITS];
    size_t grey_set[MAX_ALLOC_PAGE_SIZE/BLOCK_BITS];
    size_t black_set[MAX_ALLOC_PAGE_SIZE/BLOCK_BITS];
    size_t permanent[MAX_ALLOC_PAGE_SIZE/BLOCK_BITS];
    size_t num_objs;
    struct plisp_cons *objs;
    struct obj_allocs *next;
};

// pool for allocating cons sized objects
static struct obj_allocs *conspool = NULL;
static uintptr_t stack_bottom;

static void plisp_gc_collect();

static bool get_bit(size_t *array, size_t i) {
    return array[i/BLOCK_BITS]
        & (1lu << (i % BLOCK_BITS));
}

static void set_bit(size_t *array, size_t i, bool val) {
    if (val) {
        array[i/BLOCK_BITS] |= (1lu << (i % BLOCK_BITS));
    } else {
        array[i/BLOCK_BITS] &= ~(1lu << (i % BLOCK_BITS));
    }
}

static void set_bit_wide(size_t *array, size_t idx, int val, int width) {
    int mask = ((int)pow(2, width)) - 1;
    int i = idx * width;
    array[i/BLOCK_BITS] &= ~(mask << (i % BLOCK_BITS));
    array[i/BLOCK_BITS] |= ((mask & val) << (i % BLOCK_BITS));
}

static void get_bit_wide(size_t *array, size_t idx, int width) {
    int mask = ((int)pow(2, width)) - 1;
    int i = idx * width;
    return array[i/BLOCK_BITS] & (mask << (i % BLOCK_BITS));
}

// gets the index of the first free 0 bit
static size_t first_free(const size_t *array, size_t len) {
    for (size_t i = 0; i < len/BLOCK_BITS; ++i) {
        size_t block = array[i];
        if (block != 0xfffffffffffffffflu) {
            for (size_t j = 0; j < BLOCK_BITS; ++j) {
                if (!(block & (1lu << j))) {
                    return i*BLOCK_BITS + j;
                }
            }
        }
    }
    return len;
}

static void *allocate_or_null(struct obj_allocs *pool) {
    if (pool == NULL) {
        return NULL;
    }

    size_t i = first_free(pool->allocated, pool->num_objs);
    if (i == pool->num_objs) {
        return allocate_or_null(pool->next);
    }

    set_bit(pool->allocated, i, 1);
    return pool->objs + i;
}

static struct obj_allocs *make_obj_allocs(struct obj_allocs *next) {
    struct obj_allocs *allocs = malloc(sizeof(struct obj_allocs));

    memset(allocs->allocated, 0, sizeof(allocs->allocated));
    memset(allocs->grey_set, 0, sizeof(allocs->grey_set));
    memset(allocs->black_set, 0, sizeof(allocs->black_set));
    memset(allocs->permanent, 0, sizeof(allocs->permanent));
    memset(allocs->types, 0, sizeof(allocs->types));

    allocs->num_objs = MAX_ALLOC_PAGE_SIZE; // TODO: maybe set this dynamically
    allocs->objs = malloc(allocs->num_objs * sizeof(struct plisp_cons));
    allocs->next = next;

    return allocs;
}


plisp_t plisp_alloc_obj(uintptr_t tags) {
    void *ptr = allocate_or_null(conspool);
    if (ptr == NULL) {
        plisp_init_gc(); // TODO: move this call
        // It only needs to be called once at the start of the program
        plisp_gc_collect();

        printf("Full Page. Resizing\n");
        conspool = make_obj_allocs(conspool);
        ptr = allocate_or_null(conspool);
        assert(ptr != NULL);
    }
    printf("Allocated: %X\n", ptr);
    return ((plisp_t) ptr) | tags;
}

bool plisp_heap_allocated(plisp_t obj) {
    return plisp_c_consp(obj)
        || plisp_c_symbolp(obj)
        || plisp_c_vectorp(obj)
        || plisp_c_stringp(obj)
        || plisp_c_customp(obj);
}

static void plisp_gc_set_permanent(plisp_t obj, bool flag) {
    assert(plisp_heap_allocated(obj));
    for (struct obj_allocs *allocs = conspool; allocs != NULL;
         allocs = allocs->next) {

        if (obj >= (plisp_t) allocs->objs
            && obj < (plisp_t) (allocs->objs + allocs->num_objs)) {

            size_t idx = ((obj & ~LOTAGS) - (uintptr_t) allocs->objs)
                / sizeof(struct plisp_cons);
            set_bit(allocs->permanent, idx, flag);
            return;
        }
    }
    assert(false);
}

void plisp_gc_permanent(plisp_t obj) {
    plisp_gc_set_permanent(obj, true);
}

void plisp_gc_nopermanent(plisp_t obj) {
    plisp_gc_set_permanent(obj, false);
}

void plisp_init_gc() {
    static int initted;
    FILE *statfp;

    if (initted)
        return;

    initted = 1;

    statfp = fopen("/proc/self/stat", "r");
    assert(statfp != NULL);
    fscanf(statfp,
           "%*d %*s %*c %*d %*d %*d %*d %*d %*u "
           "%*u %*u %*u %*u %*u %*u %*d %*d "
           "%*d %*d %*d %*d %*u %*u %*d "
           "%*u %*u %*u %lu", &stack_bottom);
    fclose(statfp);
}

static void gc_get_roots_from_stack(struct obj_allocs *pool) {
    uintptr_t stack_top;
    stack_top = __builtin_frame_address(0);
    printf("Stack Top: %X\n", stack_top);
    printf("Stack Bottom: %X\n", stack_bottom);
    if (pool == NULL) {
        return;
    }

    uintptr_t ptr;
    uintptr_t objptr = pool->objs;
    for (uintptr_t* p = stack_top; p <= stack_bottom; p += 8) {
        ptr = *p;
        if (ptr >= objptr &&
            ptr < objptr + pool->num_objs * sizeof(struct plisp_cons)) {
            set_bit(pool->grey_set,
                    (ptr - objptr) / sizeof(struct plisp_cons), 1);
            set_bit(pool->white_set,
                    (ptr - objptr) / sizeof(struct plisp_cons), 0);
        }
    }

    gc_get_roots_from_stack(pool->next);
}

static void gc_get_roots_from_registers(struct obj_allocs *pool) {
    // TODO
}

static void gc_get_roots_from_perm(struct obj_allocs *pool) {
    if (pool == NULL) {
        return;
    }

    for (size_t i = 0; i < MAX_ALLOC_PAGE_SIZE/BLOCK_BITS; ++i) {
        pool->grey_set[i] |= pool->permanent[i];
        pool->white_set[i] |= ~pool->permanent[i];
    }

    gc_get_roots_from_perm(pool->next);
}
static void gc_get_roots(struct obj_allocs *pool) {
    gc_get_roots_from_stack(pool);
    gc_get_roots_from_registers(pool);
    gc_get_roots_from_perm(pool);
}

// returns 1 if no values in grey set, otherwise 0
static int plisp_gc_scan(struct obj_allocs *pool) {
    if (pool == NULL) {
        return;
    }

    plisp_cons* ptr;
    for (size_t i = 0; i < MAX_ALLOC_PAGE_SIZE; ++i) {
        if (get_bit(pool->grey_set, i)) {
            ptr = pool->objs[i];
            // TODO: add children to grey set
            set_bit(pool->grey_set, i, 0);
            set_bit(pool->black_set, i, 1);
        }
    }

    plisp_gc_scan(pool->next);


}

static void plisp_gc_collect() {
    printf("Collecting Garbage\n");
    gc_get_roots(conspool);

    // Stop the world collection
    // Loop until no values in grey set
    while (!plisp_gc_scan());

    // TODO: Collect
}
