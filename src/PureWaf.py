# This file is the main file of the PureWaf package.
# It is emphasized again that the code is only for educational purposes
# (like in CTFs) and should not be used for any malicious purposes.
# If any bugs found or you have any suggestions
# please raise an issue or pull request on the github.
# If you have any questions, please feel free to contact me.
# <childrenwlx@gmail.com>

import logging

version = '1.0-beta_v1'

def banner(version):
    return rf"""
 ____                      __        __     ___  
|  _ \ _   _ _ __ ___      \ \      / /_ _ |  _|
| |_) | | | | '__/ _ \      \ \ /\ / / _` /| |_
|  __/| |_| | | | (_) |      \ V  V / (_| \|  _|
|_|    \__,_|_|  \___/        \_/\_/ \__,_||_|

    [ PureWaf :: Pure You Hate ]
    [ Author  :: Pure Stream ]
    [ Version :: {version}]
    [ Github  :: https://github.com/PureStream108/PureWaf ]

"""

print(banner(version))