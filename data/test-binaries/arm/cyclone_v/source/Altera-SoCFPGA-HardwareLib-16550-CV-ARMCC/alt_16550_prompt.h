/*****************************************************************************
*
* Copyright 2013 Altera Corporation. All Rights Reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its contributors
* may be used to endorse or promote products derived from this software without
* specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
*****************************************************************************/

/*
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-ARMCC/alt_16550_prompt.h#1 $
 */

#ifndef ___ALT_16550_PROMPT_H___
#define ___ALT_16550_PROMPT_H___

#include "alt_16550_buffer.h"

#ifdef __cplusplus
extern "C"
{
#endif  /* __cplusplus */

/*!
 * This preprocessor definition determines the size of the buffer used to read
 * lines from the UART buffer. If long lines are expected, it may be necessary
 * to increase this value.
 *
 * To specify another size, define ALT_16550_PROMPT_PROVISION_BUFFER_SIZE
 * in your Makefile to another size.
 */
#ifndef ALT_16550_PROMPT_PROVISION_BUFFER_SIZE
#define ALT_16550_PROMPT_PROVISION_BUFFER_SIZE 512
#endif

/*!
 * This preprocessor definition determines the size of the buffer used to store
 * commands within the prompt structure. Thus commands up to the given length
 * (including the terminating NULL) is supported for callback.
 *
 * To specify another size, define ALT_16550_PROMPT_PROVISION_COMMAND_SIZE in
 * your Makefile to another size,
 */
#ifndef ALT_16550_PROMPT_PROVISION_COMMAND_SIZE
#define ALT_16550_PROMPT_PROVISION_COMMAND_SIZE 32
#endif

/*!
 * This preprocessor definition determines the maximum number of commands
 * supported for callback within the prompt structure.
 *
 * To specify another handler callback count, define
 * ALT_16550_PROMPT_PROVISION_HANDLER_COUNT in your Makefile to another value.
 */
#ifndef ALT_16550_PROMPT_PROVISION_HANDLER_COUNT
#define ALT_16550_PROMPT_PROVISION_HANDLER_COUNT 64
#endif

typedef struct ALT_16550_PROMPT_s ALT_16550_PROMPT_t;
typedef char alt_16550_prompt_command_t[ALT_16550_PROMPT_PROVISION_COMMAND_SIZE];

/*!
 * Callback definition for the prompt dispatch.
 *
 * \param       prompt
 *              The prompt structure. This is used for calling
 *              alt_16550_prompt_stop() to stop the prompt callback system.
 *
 * \param       buffer
 *              The UART buffer. This is used to do additional input or output
 *              to the UART.
 *
 * \param       argument
 *              Any arguments passed along with the command is returned as a
 *              string using this pointer.
 *
 * \param       context
 *              The context provided when the callback was registered.
 *
 * \retval      true            The default callback should be issued after
 *                              this callback completes.
 * \retval      false           No additional callbacks should be made.
 */
typedef bool (*alt_16550_prompt_callback_t)(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                                            char * argument,
                                            void * context);

typedef enum ALT_16550_PROMPT_STATE_e
{
    ALT_16550_PROMPT_STATE_INIT,
    ALT_16550_PROMPT_STATE_RUNNING,
    ALT_16550_PROMPT_STATE_EXIT
}
ALT_16550_PROMPT_STATE_t;

struct ALT_16550_PROMPT_s
{
    ALT_16550_BUFFER_t *     buffer;
    ALT_16550_PROMPT_STATE_t state;

    alt_16550_prompt_command_t  handler_command[ALT_16550_PROMPT_PROVISION_HANDLER_COUNT];
    alt_16550_prompt_callback_t handler_callback[ALT_16550_PROMPT_PROVISION_HANDLER_COUNT];
    void *                      handler_context[ALT_16550_PROMPT_PROVISION_HANDLER_COUNT];
    uint32_t                    handler_count;

    alt_16550_prompt_callback_t default_callback;
    void *                      default_context;
};

/*!
 * Initializes the given prompt dispatcher. This should be the first call made
 * after creating the prompt.
 *
 * \param       prompt
 *              The prompt handle.
 *
 * \param       buffer
 *              The UART buffer to associate with the prompt.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_prompt_init(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer);

/*!
 * Uninitializes the given prompt dispatcher.
 *
 * \param       prompt          The prompt handle.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_prompt_uninit(ALT_16550_PROMPT_t * prompt);

/*!
 * Registers a callback and context for a given command.
 *
 * \param       prompt
 *              The prompt handle.
 *
 * \param       command
 *              The command string which will trigger the callback.
 *
 * \param       callback
 *              The callback to use when the given command is called.
 *
 * \param       context
 *              The callback context to use for the above callback. When the
 *              callback is issued, this parameter will be provided to the
 *              callback.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_prompt_command_register(ALT_16550_PROMPT_t * prompt,
                                                  const char * command,
                                                  alt_16550_prompt_callback_t callback,
                                                  void * context);

/*!
 * Searches the prompt for a given command and executes it if found. Otherwise
 * the default handler is called.
 *
 * \param       prompt
 *              The prompt handle.
 *
 * \param       command
 *              The command string which will trigger the callback.
 *
 * \param       argument
 *              Arguments passed along with the command.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_prompt_command_execute(ALT_16550_PROMPT_t * prompt,
                                                 const char * command,
                                                 char * argument);

/*!
 * Runs the prompt. Lines will be continuously read from the input and
 * dispatched accordingly. To stop the system, alt_16550_prompt_stop() should
 * be called within one of the callbacks. The default callback will be issued
 * initially.
 *
 * \param       prompt
 *              The prompt handle.
 *
 * \param       default_callback
 *              Callback used for the initial callback and when commands are
 *              not found.
 *
 * \param       default_context
 *              Context for the default callback.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_prompt_start(ALT_16550_PROMPT_t * prompt,
                                       alt_16550_prompt_callback_t default_callback,
                                       void * default_context);

/*!
 * Instructs the prompt to stop processing input from the UART buffer.
 *
 * \param       prompt
 *              The prompt handle.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_prompt_stop(ALT_16550_PROMPT_t * prompt);

/*!
 * Helper utility which breaks the input up into arguments. NULL characters
 * will be injected as necessary to trim whitespaces from the strings.
 *
 * \param       input
 *              The full input string to break up.
 *
 * \param       first
 *              The first word in the input
 *
 * \param       rest
 *              The rest of the input string after the first word has been
 *              isolated.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE alt_16550_prompt_parse(char * input, char ** first, char ** rest);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif
