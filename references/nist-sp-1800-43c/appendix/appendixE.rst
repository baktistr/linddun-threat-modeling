Appendix E: System Description
==============================

This appendix presents the system context for the complete example in the form of individual PANOPTIC contextual mappings for the clinical and research uses cases and multiple dataflow diagrams. The dataflow diagrams distinguish between the clinical use case, the research use case for physical versus digital samples, and dataflows shared by the use cases.

PANOPTIC Contextual Mapping for Clinical Use Case
-------------------------------------------------

.. image:: media/Appendix-Figure2.png
   :width: 4.66663in
   :height: 8.09198in
   :alt: Analysis results of PANOPTIC Contextual Mapping for clinical use case highlight elements in PANOPTIC table


PANOPTIC Contextual Mapping for Research Use Case
-------------------------------------------------

.. image:: media/Appendix-Figure3.png
   :width: 4.6in
   :height: 8in
   :alt: Analysis results of PANOPTIC Contextual Mapping for research use case highlight elements in PANOPTIC table


Dataflow Diagram Legend 
-----------------------

.. table:: Appendix Table 4. Symbols Used in Detailed DFDsData Flow Diagrams (DFDs) created by the team to document their work, showing trust boundaries and communication paths. These diagrams support STRIDE threat analysis and help create a common architecture document for collaboration. They follow conventions

   +-----------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
   | **Element**     | **Symbol**                                                                                     | **Discussion**                                                                                                                                                                           |
   +=================+================================================================================================+==========================================================================================================================================================================================+
   | External Entity | .. image:: media/Appendix-DFDTable-Icon1.png                                                   | **Object:** A sharp-cornered rectangle.                                                                                                                                                  |
   |                 |                                                                                                |                                                                                                                                                                                          |
   |                 |                                                                                                | **Represents:** Anything outside your control. Examples include people and systems run by other organizations or even divisions.                                                         |
   +-----------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
   | Process         | .. image:: media/Appendix-DFDTable-Icon2.png                                                   | **Object:** A rounded rectangle.                                                                                                                                                         |
   |                 |                                                                                                |                                                                                                                                                                                          |
   |                 |                                                                                                | **Represents:** Any digital or physical process that generates or manipulates data, including running code, scripts, shell commands, Structured Query Language (SQL) queries, et cetera. |
   +-----------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
   | Data Store      | .. image:: media/Appendix-DFDTable-Icon3.png                                                   | **Object:** A drum.                                                                                                                                                                      |
   |                 |                                                                                                |                                                                                                                                                                                          |
   |                 |                                                                                                | **Represents:** Anywhere data are stored, including files, databases, shared memory, cloud storage services, cookies, et cetera.                                                         |
   +-----------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
   | Dataflows       | .. image:: media/Appendix-DFDTable-Icon4.png                                                   | **Object:** A double-headed arrow.                                                                                                                                                       |
   |                 |                                                                                                |                                                                                                                                                                                          |
   |                 |                                                                                                | **Represents:** All the ways that components can exchange data with one another. If a flow is unidirectional, you can represent the sending side as an empty arrow.                      |
   +-----------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
   | Human Actor     | .. image:: media/Appendix-DFDTable-Icon5.png                                                   | **Object:** A stick figure.                                                                                                                                                              |
   |                 |                                                                                                |                                                                                                                                                                                          |
   |                 |                                                                                                | **Represents:** Any human actor in the environment.                                                                                                                                      |
   +-----------------+------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Each two-dimensional object with solid lines represents a **component**. All lines connecting components represent **dataflows** that can be either digital or physical (such as a network connection or a human inserting a physical sample into a sequencer). Dataflows are shown as double-headed arrows. A **hollow arrow** on one side of a given dataflow implies that the component on that side of the dataflow is the exclusive source.

Dataflow Diagram for Clinical Use Case
--------------------------------------

.. figure:: media/Appendix-Figure4.png
   :width: 98%
   :alt: Dataflow diagram including entities, process, data stores, dataflows, and human actors in the clinical use case

 
Dataflow Diagram for Research Physical Use Case
-----------------------------------------------

.. figure:: media/Appendix-Figure5.png
   :width: 98%
   :alt: Dataflow diagram including entities, process, data stores, dataflows, and human actors in the research use case


Dataflow Diagram for Research Digital Use Case
----------------------------------------------

.. figure:: media/Appendix-Figure6.png
   :width: 98%
   :alt: Dataflow diagram including entities, process, data stores, dataflows, and human actors in the research digital use case


Shared Dataflow Diagram
-----------------------

.. figure:: media/Appendix-Figure7.png
   :width: 98%
   :alt: Dataflow diagram including entities, process, data stores, dataflows, and human actors for those shared between research and clinical
