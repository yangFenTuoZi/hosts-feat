cmake_minimum_required(VERSION 3.22.1)

project("hostsfeat")

add_library(ping SHARED
        ping.c)

add_library(nslookup SHARED
        nslookup.c)
