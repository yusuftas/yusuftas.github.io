---
title: "Caffe Python Installation with Anaconda"
date: 2018-04-07
categories: 
  - "deep-learning"
tags: 
  - "anaconda-pycaffe"
  - "caffe-compiling-errors"
  - "caffe-python-installation"
  - "pycaffe"
---

Caffe is one of the famous Deep Learning frameworks. Its main core implementation is in C++ which got my attention when I started my Phd. Other than C++ it also has wrappers/interface for Matlab, Python and command line. Matlab interface is called matcaffe and python interface is called pycaffe. In this post I will talk about my observations and experiences in installation process of pycaffe.

First of all, you might ask, why Caffe or even pycaffe ?. Caffe is one of the first frameworks I learned,modified,extended etc. So I wanted to go back to it for this instance. Actually main reason is that its C++ core and python interface makes it easy for me to use OpenCV with it which will be the next topic I will post.

In this post I won't go into too much details of Caffe / pycaffe. This post is mainly about installation and the problems you can face during installation.

<!--more-->

To be able to use Caffe's python interface, pycaffe, in general you can follow two approaches:

1. First method is to compile Caffe by source code. While it is not that hard to compile, you will need to install several dependencies to be able to successfully compile Caffe. Also to compile pycaffe, you will need to have several packages installed. If there is a mismatch between library versions that is used to compile Anaconda binaries with the libraries in your system, you will have such a hard time to fix these problems. You will get weird run time errors while you are even just trying to import Caffe in python. Most probable causes to this problem are the libraries **protobuf, readline,opencv**. If you will be compiling Caffe from source code, make sure there is only one version of these libraries in your system. Also make sure that versions match with the Python packages. For example in linux, to check what version is available in runtime linker :
    
    `ldconfig -p | grep libreadline` This command will show what version of libreadline your runtime linker will have access to. If you see that you have two versions of readline, things might get complicated. **Recent version of Caffe will need a recent version of protobuf library which might need a recent version of readline.** But old readline version in your system might be needed by many core parts of your distribution such as network-manager, ubuntu-desktop, wpa-supplicant etc. Be careful if you are trying "**sudo apt-get remove libreadline**" for the old version, this might also remove some core parts in your system. **Check what will be automatically removed along with readline**. I have mistakenly removed my network-manager and wpasupplicant while trying to remove old libreadline version which caused me a lot of trouble to connect to the wireless networks to install them back again :) If you push more and do more crazy things, you might get a warning :
    
    ![](/assets/img/IMG-20180405-WA0016.jpg)
    
    I haven't completed that of course, probably nothing good would've happened :)
    

3. Now the second version is much easier and no risks involved. You can separately , in a new environment with Anaconda, install pycaffe. To do that, you need to first create a new environment within Anaconda, this will create a bare minimum Anaconda environment without any additional libraries you installed :
    
    `conda create -n mycaffe python source activate mycaffe`
    
    **Don't forget that every time you want to use this new Caffe environment, you need to activate it**, you can also at any time deactivate it with "**source deactivate**". After you activate the new environment, we will start installing libraries :
    
    `conda install opencv conda install caffe`
    
    This will install all the required dependencies etc. It should be able to install without any problem, it is a new clean environment. After installation complete open a python console and check if everything is working :
    
    `import caffe print(caffe.__version__)`
    
    So **if you can see it prints the version number of the Caffe, then you are good to start using Pycaffe**.

That is it for this post, let me know if you face a problem with installation; I've faced so many problems with Caffe, so I believe I might help you with your problem :) And as always, keep learning.
