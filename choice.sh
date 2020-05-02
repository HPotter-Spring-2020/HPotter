#! /bin/bash -e
# https://gist.github.com/drsjb80/ab0b1f8b4150937493f2d28fd6d77767
# use ./choice [command line #] in terminal to execute command from a .choice file
filename=".choices"

# see if there's a '-f filename'
if [[ "$1" == "-f" ]]
then
    # use it for the commands
    filename="$2"
    shift
    shift
elif [[ ! -r $filename ]]
then
    # otherwise, look in the current directory for a '.choices' file and
    # use that. if there isn't one here, look in parent directories until
    # there are no more parent directories.
    prefix=.
    while true
    do
        absolute=$(cd $prefix; pwd)

        if [[ -r "$absolute/$filename" ]]
        then
            filename=$absolute/$filename
            break
        fi

        if [[ "$absolute" = "/" ]]
        then
            echo "No $filename file found, exiting"
            exit 1
        fi

        prefix=$prefix/..
    done
fi

# if the user supplied a number on the command line, use that.
if [[ "$1" != "" ]]
then
    a=$1
    shift
    echo `sed -ne "$a,$a p" "$filename"` "$*"
    eval `sed -ne "$a,$a p" "$filename"` "$*"
    exit
fi

IFS=$'\n'

# otherwise, give them a choice and remember it in their history.
select CHOICE in `cat $filename`
do
    history -s "$CHOICE"
    eval $CHOICE $*
    break
done