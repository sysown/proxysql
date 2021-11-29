screen -ls | grep '(Detached)' | awk '{print $1}' | xargs -I % -t screen -X -S % quit
