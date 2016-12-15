# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Introspection state."""

from automaton import machines


class States(object):
    """States of an introspection."""
    # received introspection data from a nonexistent node
    # active - the inspector performs an operation on the node
    enrolling = 'enrolling'
    # an error appeared in a previous introspection state
    # passive - the inspector doesn't perform any operation on the node
    error = 'error'
    # introspection finished successfully
    # passive
    finished = 'finished'
    # processing introspection data from the node
    # active
    processing = 'processing'
    # processing stored introspection data from the node
    # active
    reapplying = 'reapplying'
    # received a request to start node introspection
    # active
    starting = 'starting'
    # waiting for node introspection data
    # passive
    waiting = 'waiting'

    @classmethod
    def all(cls):
        """Return a list of all states."""
        return [cls.starting, cls.waiting, cls.processing, cls.finished,
                cls.error, cls.reapplying, cls.enrolling]


class Events(object):
    """Events that change introspection state."""
    # cancel a waiting node introspection
    # API, user
    abort = 'abort'
    # mark an introspection failed
    # internal
    error = 'error'
    # mark an introspection finished
    # internal
    finish = 'finish'
    # process node introspection data
    # API, introspection image
    process = 'process'
    # process stored node introspection data
    # API, user
    reapply = 'reapply'
    # initialize node introspection
    # API, user
    start = 'start'
    # mark an introspection timed-out waiting for data
    # internal
    timeout = 'timeout'
    # mark an introspection waiting for image data
    # internal
    wait = 'wait'

    @classmethod
    def all(cls):
        """Return a list of all events."""
        return [cls.process, cls.reapply, cls.timeout, cls.wait, cls.abort,
                cls.error, cls.finish]

# Error transition is allowed in any state.
State_space = [
    {
        'name': States.enrolling,
        'next_states': {
            Events.error: States.error,
            Events.process: States.processing,
        },
    },
    {
        'name': States.error,
        'next_states': {
            Events.abort: States.error,
            Events.error: States.error,
            Events.reapply: States.reapplying,
            Events.start: States.starting,
        },
    },
    {
        'name': States.finished,
        'next_states': {
            Events.finish: States.finished,
            Events.reapply: States.reapplying,
            Events.start: States.starting
        },
    },
    {
        'name': States.processing,
        'next_states': {
            Events.error: States.error,
            Events.finish: States.finished,
        },
    },
    {
        'name': States.reapplying,
        'next_states': {
            Events.error: States.error,
            Events.finish: States.finished,
            Events.reapply: States.reapplying,
        },
    },
    {
        'name': States.starting,
        'next_states': {
            Events.error: States.error,
            Events.start: States.starting,
            Events.wait: States.waiting,
        },
    },
    {
        'name': States.waiting,
        'next_states': {
            Events.abort: States.error,
            Events.process: States.processing,
            Events.start: States.starting,
            Events.timeout: States.error,
        },
    },
]

FSM = machines.FiniteMachine.build(State_space)
FSM.default_start_state = States.finished
