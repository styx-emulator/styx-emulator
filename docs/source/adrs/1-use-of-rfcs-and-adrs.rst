.. _use_of_rfcs_and_adrs_adr:

1. Use of RFCs and ADRs
#######################

Use of RFCs and ADRs
********************

Status: Valid

Overview
========

Styx as a project needs a uniform way to record past or current decision
making, and a way to propose new decisions to be made.

Context
=======

Current decisions are not really documented anywhere and it requires effort
from current developers to help get new developers up to speed or find "the
right way to do things". While there is pretty extensive API documentation,
and there are some docs that show examples of how to perform some high level
actions using the ``styx`` library, that is not enough.

Having a method to record the past actions and the decision making that went
into them is vital to understanding how the project got to where it currently
is and what other options were considered, prototyped, or omitted in the search
for a solution to a problem.

As it currently stands, the internal development team makes decisions and
regularly plans new features -- from the outside without any far off goal or
objective. What does this current feature just merged have to do with a goal?
And what is the next goal? Currently only the current tasking and the
soon-to-be tasking are updated with any form of labels, and due to the small
size of the team that is unlikely to change.

Decision
========

To accommodate the current size, state, and abilities of the team (and the
interests!), *both* an RFC and an ADR process are going to be added. This
will separate the concerns of the RFCs and ADRs to allow ADRs to **only**
focus on the decision that have been made (whether back-filled or live), and
allow for the RFCs to focus on the propositions of new decisions to be made.
As a part of the RFC acceptance or rejection a new ADR is created to reflect
the actions taken.

The structure and guidelines for ADRs will be defined in :ref:`adrs`, and
RFCs will be defined in :ref:`rfcs`.

Selfishly, this will hopefully keep more focus of the actual decision and the
reasoning behind it documented in the ADR, and leave any niche technical
details and planning, architecture design and iteration tucked into RFCs
documents.

I full expect this to change in the future.

Consequences
============

Notes
=====
