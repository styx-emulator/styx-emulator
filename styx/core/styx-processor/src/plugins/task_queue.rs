// SPDX-License-Identifier: BSD-2-Clause
use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{mpsc, Arc, Mutex};

use log::trace;
use styx_errors::UnknownError;

use super::{Plugin, UninitPlugin};
use crate::core::{ProcessorCore, VcpuCore};
use crate::executor::time::GlobalDelta;
use crate::processor::{PerVcpuSlice, Processor};

pub struct TaskHandle<T> {
    recv: mpsc::Receiver<T>,
}

impl<T> TaskHandle<T> {
    /// Block until the task is run and return the result of the task.
    pub fn join(self) -> T {
        self.recv.recv().unwrap()
    }
}

type TaskFn = Box<dyn FnOnce(TaskContext) + Send>;
pub struct TaskContext<'a> {
    pub core: &'a mut ProcessorCore,
    pub vcpus: &'a mut PerVcpuSlice<VcpuCore>,
}
impl<'a> From<&'a mut Processor> for TaskContext<'a> {
    fn from(value: &'a mut Processor) -> Self {
        TaskContext {
            core: &mut value.core,
            vcpus: &mut value.vcpus,
        }
    }
}

#[allow(dead_code)]
struct Task {
    function: TaskFn,
}

/// Add tasks to the queue. Freely cloneable.
#[derive(Clone)]
pub struct TaskQueueHandle {
    tasks: Arc<Mutex<VecDeque<Task>>>,
}
impl Debug for TaskQueueHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskQueue").finish()
    }
}
impl TaskQueueHandle {
    /// Add a task to the queue. The task will be run on the next processor tick.
    ///
    /// [`TaskHandle::join()`] allows you to get the returned value and block until the task is
    /// completed. However, the task will run and complete even if not joined.
    ///
    /// Tasks are run on vcpu 0.
    pub fn add_task<T: Send + 'static>(
        &self,
        task: impl FnOnce(TaskContext) -> T + Send + 'static,
    ) -> TaskHandle<T> {
        let (send, recv) = mpsc::channel();
        let new_fn = move |context: TaskContext| {
            let res = task(context);
            // ok if send errors here, it just means the join handle was dropped
            let _ = send.send(res);
        };
        let task = Task {
            function: Box::new(new_fn),
        };
        self.tasks.lock().unwrap().push_back(task);
        TaskHandle { recv }
    }
}

impl Default for TaskQueueHandle {
    fn default() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

/// Plugin that allows for asynchronous tasks to run on the mutable processor.
///
/// Since the processor is taken by `&mut` during execution, users cannot
/// introspect or otherwise modify the processor until it is done executing.
/// The exception to this are hooks and plugins that can be added and execute
/// at different times in the processor lifecycle.
///
/// This plugin makes running code on a running processor easier by adding a
/// task system that runs closures on the mutable processor during the tick
/// phase. Tasks are queued via [`TaskQueueHandle::add_task()`] and dequeued in
/// the plugin's tick. The [`TaskQueueHandle`] can be cloned freely so tasks can
/// be added during processor execution.
///
/// See [`TaskQueuePlugin::new()`] and [`TaskQueueHandle::add_task()`].
#[derive(Default)]
pub struct TaskQueuePlugin {
    task_queue: TaskQueueHandle,
}

impl TaskQueuePlugin {
    /// Create the executor and [TaskQueueHandle] to add tasks to the queue.
    pub fn new() -> (Self, TaskQueueHandle) {
        let task_queue = TaskQueueHandle::default();
        let task_queue_rtn = task_queue.clone();
        (Self { task_queue }, task_queue_rtn)
    }
}

impl Plugin for TaskQueuePlugin {
    fn tick(
        &mut self,
        core: &mut ProcessorCore,
        _delta: &GlobalDelta,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        trace!("exec task queue");
        let mut tasks = self.task_queue.tasks.lock().unwrap();
        // run each task in queue on cpu 0
        while let Some(task) = tasks.pop_front() {
            let context = TaskContext { core, vcpus };
            (task.function)(context);
        }
        // drop tasks lock
        trace!("done exec task queue");

        Ok(())
    }

    fn name(&self) -> &str {
        "task queue plugin"
    }
}

impl UninitPlugin for TaskQueuePlugin {
    fn init(
        self: Box<Self>,
        _proc: &mut crate::processor::BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        Ok(self)
    }
}
