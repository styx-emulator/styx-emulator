.. _rfcs:

Requests For Comments (RFC's)
=============================

In the ``styx`` emulator project RFCs are used to propose new larger
features, far off goals, or changes in current way of doing things etc.

In general the process should follow a simple state machine:

* Draft

  This stage is not explicitly mandatory, but if the RFC sponsor does
  not have their idea completely fleshed out this is an opportunity to
  get ideas and solicit feedback, the state should be updated from
  draft if the RFC is going to continue through the process. If the
  RFC is going to be abandoned, please merge the RFC and change
  the status to ``Draft -- abandoned`` and link to an ADR that details
  the decisions that led to abandoning the RFC in question.

* Proposed

  Once the RFC is merged to the ``main`` branch it now becomes in review,
  committing it to the source code repository in this state is to provide
  ample time for people to respond to a new issue / Merge Request and
  consolidate the purpose of the individual items to either the creation
  of or the discussion of the RFC. Once proposed, it immediately enters
  review until it is decided on.

* Review

  The RFC is now in review, a new merge request should be opened that
  contains a new :ref:`ADR <adrs>` referencing the initial RFC, and populated
  with the current context and overview. Contributors can add any notes,
  context and additions to the decision until a final decision is reached.

* Decision

  The RFC is now either accepted or rejected, the outcome of the
  decision should now be recorded into the ADR, and the status of the
  RFC updated.

Make sure to update this ``toctree`` with each newly added RFC

**TODO**: make an ``xtask`` to automate this

Format
######

* Status

  A 1 word description to describe the current state of the RFC

  * Draft

    Only in rare cases should something be merged into ``main`` in
    a Draft state. Ideally this would only exist in a Draft state while
    as a Draft in a Merge Request, where it would be merged in the
    "Proposed" state

  * Proposed

    Once an RFC has been merged into ``main`` then it is a proposed RFC,
    when review would occur.

  * Accepted

    If the RFC is accepted then its status should be updated as such
    (in addition to a new ADR detailing the decision process)

  * Rejected

    If the RFC is rejected then its status should be updated as such
    (in addition to a new ADR detailing the decision process)

* Summary

  A quick sentence or two that describes what this is about.

* Motivation

  A description that precisely outlines what problem this RFC is going
  to attempt to solve, prevent, or work against/towards.

* Details

  As detailed as required, describe all stages of the new process,
  architecture, procedure, artifact etc. This should be the majority
  of the RFC

* Drawbacks/Alternatives

  Any perceived drawback/alternatives, this not only should be attempting
  to get ahead of potential problems (or at least enumerate them), but
  also served to show that the sponsor of the RFC put effort into thinking
  about the ramifications of their idea. No one idea is perfect.

* Future Work

  If this RFC is intended to be a first stage of something larger, then
  this section is probably going to be important to the review. Anything
  that will have a "next step" should probably at least have some
  thought and best effort estimation of the extra work, maintenance or
  overhead that the idea is going to incur on the project.


Additionally, please make all RFC's use restructured text and get added to the ``toctree``
on this page. The files should be named starting with an increasing number 1 more than
the existing RFC's in the source tree (and be located at ``./docs/source/rfcs/*.rst``).
After the number, a hyphen separated title should follow.

A good example would look like eg.

.. code::

   1-use-of-rfcs-and-adrs.rst


RFC List
########

.. toctree::
   :caption: RFC List

   rfcs/1-repository-automation
   rfcs/2-mmu
   rfcs/3-unified-configuration
