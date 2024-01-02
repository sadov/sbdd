/* 
 * Proxy block device target based on standard Linux Device Mapper framework
 *
 * Copyright (C) 2023 Oleg Sadov <oleg.sadov@gmail.com>
 *
 * This file is released under the GPL.
 */

#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>

struct pbdd_device {
        struct dm_dev *dev;
        sector_t start;
};

static int pbdd_target_map(struct dm_target *ti, struct bio *bio)
{
        struct pbdd_device *mdt = (struct pbdd_device *) ti->private;
        pr_info("\n<<in function pbdd_target_map \n");

	bio_set_dev(bio, mdt->dev->bdev);

        switch (bio_op(bio)) {
        case REQ_OP_READ:
                pr_info("\n pbdd_target_map : bio is a read request.... \n");
                break;
        case REQ_OP_WRITE:
                pr_info("\n pbdd_target_map : bio is a write request.... \n");
                break;
        case REQ_OP_DISCARD:
                pr_info("\n pbdd_target_map : bio is a drop request.... \n");
                break;
        default:
                return DM_MAPIO_KILL;
        }

	submit_bio(bio);

        pr_info("\n>>out function pbdd_target_map \n");       
        return DM_MAPIO_SUBMITTED;
}


static int 
pbdd_target_ctr(struct dm_target *ti,unsigned int argc,char **argv)
{
        struct pbdd_device *mdt;

        pr_info("\n >>in function pbdd_target_ctr \n");

        if (argc != 1) {
                pr_err("\n Invalid no.of arguments.\n");
                ti->error = "Invalid argument count";
                return -EINVAL;
        }

        mdt = kmalloc(sizeof(struct pbdd_device), GFP_KERNEL);

        if(mdt==NULL)
        {
                pr_err("\n Mdt is null\n");
                ti->error = "dm-pbdd_target: Cannot allocate linear context";
                return -ENOMEM;
        }       

        mdt->start=(sector_t)0;
        
        if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &mdt->dev)) {
                ti->error = "dm-pbdd_target: Device lookup failed";
        	kfree(mdt);
        	pr_err("\n>>out function pbdd_target_ctr with error\n");           
        	return -EINVAL;
        }

        ti->private = mdt;


        pr_info("\n>>out function pbdd_target_ctr \n");                       
        return 0;
}

static void pbdd_target_dtr(struct dm_target *ti)
{
        struct pbdd_device *mdt = (struct pbdd_device *) ti->private;
        pr_info("\n<<in function pbdd_target_dtr \n");        
        dm_put_device(ti, mdt->dev);
        kfree(mdt);
        pr_info("\n>>out function pbdd_target_dtr \n");               
}

static struct target_type pbdd_target = {
        .name = "pbdd_target",
        .version = {1,0,0},
        .module = THIS_MODULE,
        .ctr = pbdd_target_ctr,
        .dtr = pbdd_target_dtr,
        .map = pbdd_target_map,
};
        
module_dm(pbdd);

MODULE_AUTHOR("Oleg Sadov <oleg.sadov@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " proxy block device target");
MODULE_LICENSE("GPL");
