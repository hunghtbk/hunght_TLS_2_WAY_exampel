ServerIP=10.158.14.149
User=hung.hoang
Pass=Thaibinhmuahe17
ServerDir=/data001/hung.hoang/a35/
ServerSourceDir=$ServerDir
ServerScript=server.sh

sync_folder() {
    FolderName=$1
    
    #read -p "Sync $FolderName? [y]\n " -n 1 yn
	yn=1

    case $yn in
        [nN]*)  echo
                echo "Skip sync $FolderName."
                echo;;
            *)  rsync -avz --no-perms --no-owner --no-group --progress --exclude '.git' --rsh="sshpass -p $Pass ssh -l $User" $FolderName $ServerIP:$ServerSourceDir/$FolderName
				echo "Finish syncing $FolderName to server.";;        
    esac
}

cd /cygdrive/d/1.hunght/2.Project/4.Qt/
echo "Move to $PWD"

sync_folder TLS2Way/

sshpass -p $Pass ssh -t $User@$ServerIP "$ServerDir/rtm-handler/server.sh"


