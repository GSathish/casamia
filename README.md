Contiki with Casa Mia
============================

This fork of Contiki adds Casa Mia, a programming abstraction framework for IoT-based WSNs. Casa Mia allows you to create simple "tasks", called Casa Mia tasks, that can be installed in your IoT-based WSN at run-time.

A Casa Mia task is written in Python and allows a node to monitor one or more sensors, process their data, and send the produced output to an actuator. Alternatively, the produced output can be stored in a local resource that can be observed by another node or the user. Casa Mia tasks can be used to implement simple event-detection and control applications.

================================================================================

#### Acknowledgments

Casa Mia uses [PyMite](https://code.google.com/p/python-on-a-chip/) for interpreting Python bytecode. PyMite is a reduced Python virtual machine for constrained devices developed by Dean Hall.
