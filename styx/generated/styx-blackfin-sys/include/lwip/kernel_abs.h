#ifndef __KER_ABS__
#define __KER_ABS__
#include <limits.h>

typedef unsigned int ker_sem_id_t;
typedef unsigned int ker_thread_id_t;
typedef void (*ThreadEntryPoint)(void*);

    /* kernel init function */
extern "C" int ker_init(void *int_args);

    /* semaphore functions */
extern "C" int ker_get_semaphore(unsigned int initial_count,
                         unsigned int max_count);
extern "C" int ker_rel_semaphore(ker_sem_id_t sem_id);
extern "C" int ker_pend_semaphore(ker_sem_id_t sem_id, unsigned int timeout);
extern "C" int ker_post_semaphore(ker_sem_id_t sem_id);
extern "C" int ker_isr_post_semaphore(ker_sem_id_t sem_id);

    /* Interrupt functions */
extern "C" int ker_disable_interrupts(int pri_level);
extern "C" int ker_enable_interrupts(int pri_level);

    /* error functions */
extern "C" int ker_set_lasterror(int last_error);
extern "C" int ker_get_lasterror(void);
extern "C" int ker_get_systime(void);

    /* thread functions */
extern "C" int ker_create_thread(void *th_entry_point, void *th_args, int th_stack_sz, void* th_stack_area, int th_priority, char th_name[],ker_thread_id_t *th_id);
extern "C" void* ker_get_auxdata(void);
extern "C" void ker_set_auxdata(void* in_aux_data);
extern "C" int ker_destroy_thread(ker_thread_id_t th_id);
extern "C" int ker_set_thread_priority(ker_thread_id_t th_id,int th_pri);
extern "C" int ker_get_thread_priority(ker_thread_id_t th_id);
extern "C" int ker_get_current_thread(void);
extern "C" int ker_sleep(unsigned int sleep_time);

    /* scheduling functions */
extern "C" int ker_disable_scheduler(void);
extern "C" int ker_enable_scheduler(void);
extern "C" int ker_get_thread_status(int);

typedef enum _kernel_results_e
{
    ker_err_sem_cre = 0xFF << 8,
    ker_err_sem_timeout,
    ker_err_sem_id,
    ker_err_ints_off,
    ker_err_int_priority,
    ker_err_thread_cre,
    ker_err_thread_id,
    ker_err_thread_priority,
    ker_err_1,
    ker_err_sem_unavailable,
    ker_err_panic
}kernel_results_e;

enum
{
    ker_kPriorityLevel0  =  0,
    ker_kPriorityLevel1,
    ker_kPriorityLevel2,
    ker_kPriorityLevel3,
    ker_kPriorityLevel4,
    ker_kPriorityLevel5,
    ker_kPriorityLevel6,
    ker_kPriorityLevel7,
    ker_kPriorityLevel8,
    ker_kPriorityLevel9,
    ker_kPriorityLevel10,
    ker_kPriorityLevel11,
    ker_kPriorityLevel12,
    ker_kPriorityLevel13,
    ker_kPriorityLevel14,
    ker_kPriorityLevel15,
    ker_kPriorityLevelAll = -1
};
struct ThreadCtrlBlock
{
   void *arg;
   void (*thread_function)(void *arg);
};

#endif /* __KER_ABS__ */
