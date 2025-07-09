/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted (subject to the limitations in the disclaimer below) provided
 * that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "board.h"
#include "fsl_uart.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

void pass(void) {
    return;
}

void fail(void) {
    return;
}

#define DMA0_IRQn 0

void DMA0_IRQHandler(void)
{
    fail();
    while (1) {};
}

// sets PRIMASK then pends an interrupt
// DMA0_IRQn doesn't have a high enough priority and should be masked
void test_primask(void) {
    __set_PRIMASK(1);
    NVIC_EnableIRQ(DMA0_IRQn);
    NVIC_SetPendingIRQ(DMA0_IRQn);
    wait(10);
    NVIC_DisableIRQ(DMA0_IRQn);
    NVIC_ClearPendingIRQ(DMA0_IRQn);
    __set_PRIMASK(0);
    pass();
}

// sets PRIMASK then pends an interrupt
// DMA0_IRQn doesn't have a high enough priority and should be masked
void test_faultmask(void) {
    __set_FAULTMASK(1);
    NVIC_EnableIRQ(DMA0_IRQn);
    NVIC_SetPendingIRQ(DMA0_IRQn);
    wait(10);
    NVIC_DisableIRQ(DMA0_IRQn);
    NVIC_ClearPendingIRQ(DMA0_IRQn);
    __set_FAULTMASK(0);
    pass();
}

// sets BASEPRI then pends an interrupt with a lower priority
// should result in masked interrupt
void test_basepri(void) {
    NVIC_SetPriority(DMA0_IRQn, 3);
    __set_BASEPRI(2<<4);
    NVIC_EnableIRQ(DMA0_IRQn);
    NVIC_SetPendingIRQ(DMA0_IRQn);
    wait(10);
    NVIC_DisableIRQ(DMA0_IRQn);
    NVIC_ClearPendingIRQ(DMA0_IRQn);
    NVIC_SetPriority(DMA0_IRQn, 0);
    __set_BASEPRI(0);
    pass();
}


#define DMA1_IRQn 1
#define DMA2_IRQn 2
#define DMA3_IRQn 3

// Tests resorting the priorities of pending interrupts.
void DMA1_IRQHandler(void)
{
    NVIC_SetPendingIRQ(DMA2_IRQn);
    NVIC_SetPendingIRQ(DMA3_IRQn);
    NVIC_SetPriority(DMA3_IRQn, 0);
}
void DMA2_IRQHandler(void)
{
    fail();
}
void DMA3_IRQHandler(void)
{
    NVIC_ClearPendingIRQ(DMA1_IRQn);
    NVIC_ClearPendingIRQ(DMA2_IRQn);
    NVIC_ClearPendingIRQ(DMA3_IRQn);
    NVIC_SetPriority(DMA1_IRQn, 0);
    NVIC_SetPriority(DMA2_IRQn, 0);
    NVIC_SetPriority(DMA3_IRQn, 0);
    NVIC_DisableIRQ(DMA1_IRQn);
    NVIC_DisableIRQ(DMA2_IRQn);
    NVIC_DisableIRQ(DMA3_IRQn);
    pass();
}

void test_resort_priorities(void) {
    NVIC_EnableIRQ(DMA1_IRQn);
    NVIC_EnableIRQ(DMA2_IRQn);
    NVIC_EnableIRQ(DMA3_IRQn);
    NVIC_SetPriority(DMA1_IRQn, 0);
    NVIC_SetPriority(DMA2_IRQn, 10);
    NVIC_SetPriority(DMA3_IRQn, 11);
    NVIC_SetPendingIRQ(DMA1_IRQn);
    wait(100);
}

#define I2C0_IRQn 24

// tests entering and exiting an interrupt
void test_simple(void) {
    NVIC_EnableIRQ(I2C0_IRQn);
    NVIC_SetPendingIRQ(I2C0_IRQn);
    while (NVIC_GetEnableIRQ(I2C0_IRQn)) {

    }
    NVIC_ClearPendingIRQ(I2C0_IRQn);
    pass();
}
void I2C0_IRQHandler(void) {
    NVIC_DisableIRQ(I2C0_IRQn);
}

#define DMA4_IRQn 4
#define DMA5_IRQn 5

// tests preemption
// DMA5 should preempt DMA4 before it hits the call to 'fail'
void test_preempt(void) {
    NVIC_SetPriority(DMA4_IRQn, 1);
    NVIC_EnableIRQ(DMA4_IRQn);
    NVIC_EnableIRQ(DMA5_IRQn);
    NVIC_SetPendingIRQ(DMA4_IRQn);
    wait(100);
}

void DMA4_IRQHandler(void) {
    NVIC_SetPendingIRQ(DMA5_IRQn);
    wait(100);
    if (NVIC_GetEnableIRQ(DMA4_IRQn))
        fail();
}
void DMA5_IRQHandler(void) {
    NVIC_DisableIRQ(DMA4_IRQn);
    NVIC_DisableIRQ(DMA5_IRQn);
    NVIC_ClearPendingIRQ(DMA4_IRQn);
    NVIC_ClearPendingIRQ(DMA5_IRQn);
    NVIC_SetPriority(DMA4_IRQn, 0);
    pass();
}

#define DMA6_IRQn 6
#define DMA7_IRQn 7
#define DMA8_IRQn 8

// test heap sorting
void test_sorting(void) {
    __asm volatile("cpsid i");
    NVIC_EnableIRQ(DMA6_IRQn);
    NVIC_EnableIRQ(DMA7_IRQn);
    NVIC_EnableIRQ(DMA8_IRQn);
    NVIC_SetPriority(DMA7_IRQn, 2);
    NVIC_SetPendingIRQ(DMA8_IRQn);
    NVIC_SetPendingIRQ(DMA7_IRQn);
    NVIC_SetPendingIRQ(DMA6_IRQn);
    __asm volatile("cpsie i");
    wait(100);
    NVIC_DisableIRQ(DMA6_IRQn);
    NVIC_DisableIRQ(DMA7_IRQn);
    NVIC_DisableIRQ(DMA8_IRQn);
    NVIC_SetPriority(DMA7_IRQn, 0);
}
void DMA6_IRQHandler(void) {
    NVIC_ClearPendingIRQ(DMA8_IRQn);
    NVIC_ClearPendingIRQ(DMA7_IRQn);
    NVIC_ClearPendingIRQ(DMA6_IRQn);
    pass();
}
void DMA7_IRQHandler(void) {
    fail();
}
void DMA8_IRQHandler(void) {
    fail();
}

// the sleep at home
void wait(int count) {
    int i = 0;
    while (i < count) {
        i++;
    }
}

void quit(void) {
    int x = *((int*)0x20100000);
    while (x) {}
}


int main(void)
{
    test_simple();
    test_sorting();
    test_preempt();
    test_basepri();
    test_resort_priorities();
    test_primask();
    test_faultmask();
    quit();

    while (1)
    {

    }
}
