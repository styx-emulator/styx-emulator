.. _adrs:

Architecture Decision Records (ADR's)
=====================================

Architecture Decision Records are an easy and uniform way to report and record
the context behind decisions made in a project. For more information, please
see resources like `this one <https://github.com/joelparkerhenderson/architecture-decision-record>`_.

some highlights of things to follow (quoted from the above github link):

* Rationale: Explain the reasons for doing the particular AD. This can include the context (see below), pros and cons of various potential choices, feature comparisons, cost/benefit discussions, and more.
* Specific: Each ADR should be about one AD, not multiple ADs
* Timestamps: Identify when each item in the ADR is written. This is especially important for aspects that may change over time, such as costs, schedules, scaling, and the like
* Immutable: Don't alter existing information in an ADR. Instead, amend the ADR by adding new information, or supersede the ADR by creating a new ADR.


Format
######

We largely follow the format described `here <https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions>`_,
albeit in a slightly different order to make browsing a little faster.

Additionally, please make all ADR's use restructured text and get added to the ``toctree``
on this page. The files should be named starting with an increasing number 1 more than
the existing ADR's in the source tree (and be located at ``./docs/source/adrs/*.rst``).
After the number, a hyphen separated title should follow.

A good example would look like eg.

.. code::

   1-use-of-rfcs-and-adrs.rst

**TODO**: make an ``xtask`` to automate this

Record Format
^^^^^^^^^^^^^

* Title

  A short title that summarizes the decision in question

* Status

  The current status of the ADR, should be one of the following:

  * Valid
  * Outdated

* Overview

  A TLDR; for easier consumption

* Context

  There is a lot of context behind a decision, see the previously mentioned links for
  more information, this is the important part, and a plan on how to evaluate to either
  decide for or against this decision.

* Decision

  An ADR captures the decision behind both pursuing and not pursuing a specific action,
  provide a Y/N/Something else with an explanation.

* Consequences

  A retrospective or after-action-report (AAR), in the time after making the decision,
  what happened (good or bad) if applicable.

* Notes

  An extra information (with dates when added) that helps or provides extra information and does
  not fit anywhere else

ADR List
########

.. toctree::
   :caption: Decisions (and their record)

   adrs/1-use-of-rfcs-and-adrs
