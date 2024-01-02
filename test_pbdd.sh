#!/bin/bash

insmod sbdd.ko
insmod pbdd.ko

echo Creating PBDD device
echo
SBDD_SIZE=$(blockdev --getsize /dev/sbdd)
echo 0 $SBDD_SIZE pbdd_target /dev/sbdd | dmsetup create pbdd

if dmsetup ls | grep pbdd
then
	echo PBDD device created
else
	echo PBDD device not created
	exit -1
fi

mkfs /dev/mapper/pbdd
MNT_DIR=$(mktemp -d /tmp/mnt.XXXXXXXXXX)

end () {
	echo Unmounting $MNT_DIR/
	umount $MNT_DIR/
	rmdir $MNT_DIR
	echo Removing PBDD device
	dmsetup remove pbdd
	echo Removing modules
	rmmod pbdd
	rmmod sbdd
}

tst () {
	OUT=$(cat $MNT_DIR/tst)
	if [ $TST_MSG == $OUT ]
	then
		echo "Test passed '$OUT' == '$TST_MSG'"
	else
		echo "Test error '$OUT' != '$TST_MSG'"
		end
		exit -1
	fi
}

echo Connecting pbdd
mount /dev/mapper/pbdd $MNT_DIR
TST_MSG=test
echo test=$TST_MSG
echo $TST_MSG > $MNT_DIR/tst
tst

echo
echo Disconnecting pbdd
umount $MNT_DIR/
sleep 1
dmsetup remove pbdd
echo
echo Connecting sbdd
mount /dev/sbdd $MNT_DIR
tst

TST_MSG=1234
echo test=$TST_MSG
echo $TST_MSG > $MNT_DIR/tst
tst

echo
echo Disconnecting sbdd
umount $MNT_DIR/
echo
echo Connecting pbdd
echo 0 $SBDD_SIZE pbdd_target /dev/sbdd | dmsetup create pbdd
mount /dev/mapper/pbdd $MNT_DIR
tst
echo

end
