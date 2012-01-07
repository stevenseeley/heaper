About
=====

heaper is an Immunity Debugger plugin that is designed to help analyse heap structures under the windows environment. Often, exploitation of windows heap overflows and other vulnerabilities associated with the heap are very complex due to the dynamic nature of the heap manager.

With heaper, you can quickly visualize heap data structures, hook important heap api and determine possible exploitation paths. It is designed for analysts looking to determine the heap layout in a target process.

Currently there is full support for Windows XP. In the near future it will support Windows 7/8 heap managers.

Setup
=====

You will need to install the following prerequisites:

- [Graphviz](http://www.graphviz.org/Download.php)
- [pydot](http://code.google.com/p/pydot/)
- [pyparsing](http://sourceforge.net/projects/pyparsing/)

Then once you have completed that, copy heaper.py into your immunity debugger pycommands directory typically: 'C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands\'.

Usage
=====

simply start heaper by executing '!heaper' in Immunity Debuggers command window.

Screenshot
==========

![heap usage](https://github.com/mrmee/heaper/raw/master/heaper_usage.png "heaper usage")
![heaper hooking RtlAllocateHeap](https://github.com/mrmee/heaper/raw/master/heaper_example.png "heaper hooking RtlAllocateHeap")

License
=======

'heaper' is available under the GPLv3 license, please see the included file gpl-3.0.txt for details.
