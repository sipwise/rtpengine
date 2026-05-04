# Python demo scripts

This directory contains a set of simple Python scripts to demonstrate features
of rtpengine, from basic media proxying to more advanced media manipulation and
playback features.

Each script acts as a SIP client or server of some sort, and uses rtpengine to
manipulate media and SDP aspects. The scripts are not meant to be comprehensive
feature-wise, but rather are meant to be playgrounds that can easily be
modified and extended.

## pysip-lite

A light-weight SIP module for Python is provided, which is required to run the
demo scripts. The module is based on belle-sip (from the Linphone SDK) and
provides a simple, asyncio-based API to make and receive SIP calls.
