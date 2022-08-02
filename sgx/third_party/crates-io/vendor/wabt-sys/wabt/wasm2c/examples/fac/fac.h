#ifndef FAC_H_GENERATED_
#define FAC_H_GENERATED_
#ifdef __cplusplus
extern "C" {
#endif

#ifndef WASM_RT_INCLUDED_
#define WASM_RT_INCLUDED_

#include <stdint.h>

#ifndef WASM_RT_MAX_CALL_STACK_DEPTH
#define WASM_RT_MAX_CALL_STACK_DEPTH 500
#endif

#ifndef WASM_RT_MODULE_PREFIX
#define WASM_RT_MODULE_PREFIX
#endif

#define WASM_RT_PASTE_(x, y) x ## y
#define WASM_RT_PASTE(x, y) WASM_RT_PASTE_(x, y)
#define WASM_RT_ADD_PREFIX(x) WASM_RT_PASTE(WASM_RT_MODULE_PREFIX, x)

/* TODO(binji): only use stdint.h types in header */
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
typedef float f32;
typedef double f64;

typedef enum {
  WASM_RT_TRAP_NONE,
  WASM_RT_TRAP_OOB,
  WASM_RT_TRAP_INT_OVERFLOW,
  WASM_RT_TRAP_DIV_BY_ZERO,
  WASM_RT_TRAP_INVALID_CONVERSION,
  WASM_RT_TRAP_UNREACHABLE,
  WASM_RT_TRAP_CALL_INDIRECT,
  WASM_RT_TRAP_EXHAUSTION,
} wasm_rt_trap_t;

typedef enum {
  WASM_RT_I32,
  WASM_RT_I64,
  WASM_RT_F32,
  WASM_RT_F64,
} wasm_rt_type_t;

typedef void (*wasm_rt_anyfunc_t)(void);

typedef struct {
  uint32_t func_type;
  wasm_rt_anyfunc_t func;
} wasm_rt_elem_t;

typedef struct {
  uint8_t* data;
  uint32_t pages, max_pages;
  uint32_t size;
} wasm_rt_memory_t;

typedef struct {
  wasm_rt_elem_t* data;
  uint32_t max_size;
  uint32_t size;
} wasm_rt_table_t;

extern void wasm_rt_trap(wasm_rt_trap_t) __attribute__((noreturn));
extern uint32_t wasm_rt_register_func_type(uint32_t params, uint32_t results, ...);
extern void wasm_rt_allocate_memory(wasm_rt_memory_t*, uint32_t initial_pages, uint32_t max_pages);
extern uint32_t wasm_rt_grow_memory(wasm_rt_memory_t*, uint32_t pages);
extern void wasm_rt_allocate_table(wasm_rt_table_t*, uint32_t elements, uint32_t max_elements);
extern uint32_t wasm_rt_call_stack_depth;

#endif  /* WASM_RT_INCLUDED_ */

extern void WASM_RT_ADD_PREFIX(init)(void);

/* export: 'fac' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_facZ_ii))(u32);
#ifdef __cplusplus
}
#endif

#endif  /* FAC_H_GENERATED_ */
