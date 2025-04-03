This folder contains single header version of mocked CKB syscalls for fuzzing. One thing I learned throughout the years, is that you just cannot force people with different opinions. Some like single header libraries(like I do), some don't.

Note this file is put in version control as a reference when you don't want to clone and build by yourself. It is built on Ubuntu 24.04 with apt-installed protobuf. If you are using other platforms, chances are you might need to rebuild the protobuf generated file, and this single header file as well. You can do that via `make flatten`.
