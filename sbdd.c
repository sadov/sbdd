#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/backing-dev.h>
#include <linux/spinlock_types.h>
#ifdef BLK_MQ_MODE
#include <linux/blk-mq.h>
#endif

#define SBDD_SECTOR_SHIFT       9
#define SBDD_SECTOR_SIZE        (1 << SBDD_SECTOR_SHIFT)
#define SBDD_SIZE               PAGE_SIZE
#define SBDD_NAME               "sbdd"
#define SBDD_DEVS               4

struct sbdd {
	struct mutex            datamutex;
	wait_queue_head_t       exitwait;
	atomic_t                deleting;
	atomic_t                refs_cnt;
	sector_t                capacity;
	char                    *data[SBDD_DEVS];
	struct gendisk          *gd;
	struct request_queue    *q;
	struct workqueue_struct *wq;
#ifdef BLK_MQ_MODE
	struct blk_mq_tag_set   *tag_set;
#endif
};

struct sbdd_work {
#ifdef BLK_MQ_MODE
	struct request          *rq;
#else
	struct bio              *bio;
#endif
	struct work_struct      ws;
};

static struct sbdd      __sbdd;
static int              __sbdd_major = 0;

static sector_t sbdd_xfer(struct bio_vec* bvec, sector_t pos, int dir)
{
	char *buff = page_address(bvec->bv_page) + bvec->bv_offset;
	sector_t len = bvec->bv_len >> SBDD_SECTOR_SHIFT;
	size_t offset;
	size_t nbytes;

	if (pos + len > __sbdd.capacity)
		len = __sbdd.capacity - pos;

	offset = pos << SBDD_SECTOR_SHIFT;
	nbytes = len << SBDD_SECTOR_SHIFT;

	if (dir) {
		int i;

		/* Reverse xor with the 1st block */
		for (i = 0; i < nbytes; i++)
			__sbdd.data[SBDD_DEVS - 1][offset + i] ^= __sbdd.data[0][offset + i];

		/* Copy new data to the 1st block */
		memcpy(__sbdd.data[0] + offset, buff, nbytes);

		/* The key factor for the problem to reproduce */
		// usleep_range(10, 20);

		/* The more time we sleep - the more chance for the problem to appear */
		msleep(1);

		/* Redo xor with new data */
		for (i = 0; i < nbytes; i++)
			__sbdd.data[SBDD_DEVS - 1][offset + i] ^= buff[i];
	} else {
		memcpy(buff, __sbdd.data[0] + offset, nbytes);
	}

	pr_debug("pos=%6llu len=%4llu %s\n", pos, len, dir ? "written" : "read");

	return len;
}

#ifdef BLK_MQ_MODE

static void sbdd_submit_fn(struct work_struct *ws)
{
	struct sbdd_work *work = container_of(ws, struct sbdd_work, ws);
	struct request *rq = work->rq;
	struct req_iterator iter;
	struct bio_vec bvec;
	int dir = rq_data_dir(rq);
	sector_t pos = blk_rq_pos(rq);

	mutex_lock(&__sbdd.datamutex);

	rq_for_each_segment(bvec, rq, iter)
		pos += sbdd_xfer(&bvec, pos, dir);

	mutex_unlock(&__sbdd.datamutex);

	kfree(work);

	blk_mq_end_request(rq, BLK_STS_OK);
	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);
}

static blk_status_t sbdd_queue_rq(struct blk_mq_hw_ctx *hctx,
                                  struct blk_mq_queue_data const *bd)
{
	struct sbdd_work *work;

	if (atomic_read(&__sbdd.deleting)) {
		pr_err("unable to process bio while deleting\n");
		return BLK_STS_IOERR;
	}

	if (!atomic_inc_not_zero(&__sbdd.refs_cnt)) {
		pr_err("unable to get device ref\n");
		return BLK_STS_IOERR;
	}

	work = kzalloc(sizeof(struct sbdd_work), GFP_ATOMIC);
	if (!work) {
		pr_err("kzalloc() failed for work\n");
		if (atomic_dec_and_test(&__sbdd.refs_cnt))
			wake_up(&__sbdd.exitwait);
		return BLK_STS_IOERR;
	}

	blk_mq_start_request(bd->rq);
	work->rq = bd->rq;
	INIT_WORK(&work->ws, sbdd_submit_fn);
	queue_work(__sbdd.wq, &work->ws);

	return BLK_STS_OK;
}

static struct blk_mq_ops const __sbdd_blk_mq_ops = {
	/*
	The function receives requests for the device as arguments
	and can use various functions to process them. The functions
	used to process requests in the handler are described below:

	blk_mq_start_request()   - must be called before processing a request
	blk_mq_requeue_request() - to re-send the request in the queue
	blk_mq_end_request()     - to end request processing and notify upper layers
	*/
	.queue_rq = sbdd_queue_rq,
};

#else

static void sbdd_submit_fn(struct work_struct *ws)
{
	struct sbdd_work *work = container_of(ws, struct sbdd_work, ws);
	struct bio *bio = work->bio;
	struct bvec_iter iter;
	struct bio_vec bvec;
	int dir = bio_data_dir(bio);
	sector_t pos = bio->bi_iter.bi_sector;

	mutex_lock(&__sbdd.datamutex);

	bio_for_each_segment(bvec, bio, iter)
		pos += sbdd_xfer(&bvec, pos, dir);

	mutex_unlock(&__sbdd.datamutex);

	bio_endio(bio);
	kfree(work);

	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);
}

static blk_qc_t sbdd_make_request(struct request_queue *q, struct bio *bio)
{
	struct sbdd_work *work;

	if (atomic_read(&__sbdd.deleting)) {
		pr_err("unable to process bio while deleting\n");
		bio_io_error(bio);
		return BLK_STS_IOERR;
	}

	if (!atomic_inc_not_zero(&__sbdd.refs_cnt)) {
		pr_err("unable to get device ref\n");
		bio_io_error(bio);
		return BLK_STS_IOERR;
	}

	work = kzalloc(sizeof(struct sbdd_work), GFP_ATOMIC);
	if (!work) {
		pr_err("kzalloc() failed for work\n");
		bio_io_error(bio);
		if (atomic_dec_and_test(&__sbdd.refs_cnt))
			wake_up(&__sbdd.exitwait);
		return BLK_STS_IOERR;
	}

	work->bio = bio;
	INIT_WORK(&work->ws, sbdd_submit_fn);
	queue_work(__sbdd.wq, &work->ws);

	return BLK_STS_OK;
}

#endif /* BLK_MQ_MODE */

/*
There are no read or write operations. These operations are performed by
the request() function associated with the request queue of the disk.
*/
static struct block_device_operations const __sbdd_bdev_ops = {
	.owner = THIS_MODULE,
};

static int sbdd_create(void)
{
	int ret = 0;
	int i, j;

	/*
	This call is somewhat redundant, but used anyways by tradition.
	The number is to be displayed in /proc/devices (0 for auto).
	*/
	pr_info("registering blkdev\n");
	__sbdd_major = register_blkdev(0, SBDD_NAME);
	if (__sbdd_major < 0) {
		pr_err("call register_blkdev() failed with %d\n", __sbdd_major);
		return -EBUSY;
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));
	__sbdd.capacity = (sector_t)SBDD_SIZE >> SBDD_SECTOR_SHIFT;

	pr_info("allocating data\n");
	for (i = 0; i < SBDD_DEVS; i++) {
		__sbdd.data[i] = (char*)get_zeroed_page(GFP_KERNEL);
		if (!__sbdd.data[i]) {
			pr_err("get_zeroed_page() failed\n");
			return -ENOMEM;
		}
	}

	pr_info("initializing data\n");
	for (i = 0; i < SBDD_DEVS - 1; i++)
		get_random_bytes(__sbdd.data[i], SBDD_SIZE);

	for (i = 0; i < SBDD_SIZE; i++) {
		__sbdd.data[SBDD_DEVS - 1][i] = __sbdd.data[0][i];
		for (j = 1; j < SBDD_DEVS - 1; j++)
			__sbdd.data[SBDD_DEVS - 1][i] ^= __sbdd.data[j][i];
	}

	pr_info("allocating workqueue\n");
	__sbdd.wq = alloc_workqueue(SBDD_NAME "_wq", WQ_UNBOUND, 0);
	if (!__sbdd.wq) {
		pr_err("alloc_workqueue() failed\n");
		return -ENOMEM;
	}

	mutex_init(&__sbdd.datamutex);
	init_waitqueue_head(&__sbdd.exitwait);
	atomic_set(&__sbdd.refs_cnt, 1);

#ifdef BLK_MQ_MODE
	pr_info("allocating tag_set\n");
	__sbdd.tag_set = kzalloc(sizeof(struct blk_mq_tag_set), GFP_KERNEL);
	if (!__sbdd.tag_set) {
		pr_err("unable to alloc tag_set\n");
		return -ENOMEM;
	}

	/* Number of hardware dispatch queues */
	__sbdd.tag_set->nr_hw_queues = 1;
	/* Depth of hardware dispatch queues */
	__sbdd.tag_set->queue_depth = 128;
	__sbdd.tag_set->numa_node = NUMA_NO_NODE;
	__sbdd.tag_set->ops = &__sbdd_blk_mq_ops;

	ret = blk_mq_alloc_tag_set(__sbdd.tag_set);
	if (ret) {
		pr_err("call blk_mq_alloc_tag_set() failed with %d\n", ret);
		return ret;
	}

	/* Creates both the hardware and the software queues and initializes structs */
	pr_info("initing queue\n");
	__sbdd.q = blk_mq_init_queue(__sbdd.tag_set);
	if (IS_ERR(__sbdd.q)) {
		ret = (int)PTR_ERR(__sbdd.q);
		pr_err("call blk_mq_init_queue() failed witn %d\n", ret);
		__sbdd.q = NULL;
		return ret;
	}
#else
	pr_info("allocating queue\n");
	__sbdd.q = blk_alloc_queue(GFP_KERNEL);
	if (!__sbdd.q) {
		pr_err("call blk_alloc_queue() failed\n");
		return -EINVAL;
	}
	blk_queue_make_request(__sbdd.q, sbdd_make_request);
#endif /* BLK_MQ_MODE */

	/* Configure queue */
	blk_queue_logical_block_size(__sbdd.q, SBDD_SECTOR_SIZE);
	__sbdd.q->backing_dev_info->capabilities |= BDI_CAP_STABLE_WRITES;

	/* A disk must have at least one minor */
	pr_info("allocating disk\n");
	__sbdd.gd = alloc_disk(1);

	/* Configure gendisk */
	__sbdd.gd->queue = __sbdd.q;
	__sbdd.gd->major = __sbdd_major;
	__sbdd.gd->first_minor = 0;
	__sbdd.gd->fops = &__sbdd_bdev_ops;
	/* Represents name in /proc/partitions and /sys/block */
	scnprintf(__sbdd.gd->disk_name, DISK_NAME_LEN, SBDD_NAME);
	set_capacity(__sbdd.gd, __sbdd.capacity);

	/*
	Allocating gd does not make it available, add_disk() required.
	After this call, gd methods can be called at any time. Should not be
	called before the driver is fully initialized and ready to process reqs.
	*/
	pr_info("adding disk\n");
	add_disk(__sbdd.gd);

	return ret;
}

static void sbdd_delete(void)
{
	int i;

	atomic_set(&__sbdd.deleting, 1);
	atomic_dec(&__sbdd.refs_cnt);
	wait_event(__sbdd.exitwait, !atomic_read(&__sbdd.refs_cnt));

	if (__sbdd.wq) {
		pr_info("destroying workqueue\n");
		flush_workqueue(__sbdd.wq);
		destroy_workqueue(__sbdd.wq);
	}

	/* gd will be removed only after the last reference put */
	if (__sbdd.gd) {
		pr_info("deleting disk\n");
		del_gendisk(__sbdd.gd);
	}

	if (__sbdd.q) {
		pr_info("cleaning up queue\n");
		blk_cleanup_queue(__sbdd.q);
	}

	if (__sbdd.gd)
		put_disk(__sbdd.gd);

#ifdef BLK_MQ_MODE
	if (__sbdd.tag_set && __sbdd.tag_set->tags) {
		pr_info("freeing tag_set\n");
		blk_mq_free_tag_set(__sbdd.tag_set);
	}

	if (__sbdd.tag_set)
		kfree(__sbdd.tag_set);
#endif

	pr_info("freeing data\n");
	for (i = 0; i < SBDD_DEVS; i++) {
		if (__sbdd.data[i])
			free_page((unsigned long)__sbdd.data[i]);
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));

	if (__sbdd_major > 0) {
		pr_info("unregistering blkdev\n");
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		__sbdd_major = 0;
	}
}

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_init(void)
{
	int ret = 0;

	pr_info("starting...\n");
	ret = sbdd_create();

	if (ret) {
		pr_warn("starting failed\n");
		sbdd_delete();
	} else {
		pr_info("starting complete\n");
	}

	return ret;
}

/*
Note __exit is for the compiler to place this code in a special ELF section.
Sometimes such functions are simply discarded (e.g. when module is built
directly into the kernel). There is also __exitdata note.
*/
static void __exit sbdd_exit(void)
{
	pr_info("exiting...\n");
	sbdd_delete();
	pr_info("exiting complete\n");
}

static int sbdd_consistency_check(char *buf, struct kernel_param const *kp)
{
	int written;
	int i, j;

	pr_info("performing check\n");
	written = snprintf(buf, PAGE_SIZE, "ok\n");
	mutex_lock(&__sbdd.datamutex);

	for (i = 0; i < SBDD_SIZE; i++) {
		char byte = __sbdd.data[0][i];

		for (j = 1; j < SBDD_DEVS - 1; j++)
			byte ^= __sbdd.data[j][i];

		if (byte != __sbdd.data[SBDD_DEVS - 1][i]) {
			written = snprintf(buf, PAGE_SIZE, "byte %d check failed\n", i);
			break;
		}
	}

	mutex_unlock(&__sbdd.datamutex);
	return written;
}

static int sbdd_consistency_reset(char const *buf, struct kernel_param const *kp)
{
	int i, j;

	pr_info("resetting data\n");
	mutex_lock(&__sbdd.datamutex);

	for (i = 0; i < SBDD_DEVS - 1; i++)
		get_random_bytes(__sbdd.data[i], SBDD_SIZE);

	for (i = 0; i < SBDD_SIZE; i++) {
		__sbdd.data[SBDD_DEVS - 1][i] = __sbdd.data[0][i];
		for (j = 1; j < SBDD_DEVS - 1; j++)
			__sbdd.data[SBDD_DEVS - 1][i] ^= __sbdd.data[j][i];
	}

	mutex_unlock(&__sbdd.datamutex);
	return 0;
}

static struct kernel_param_ops const sbdd_consistency_ops = {
	.set = sbdd_consistency_reset,
	.get = sbdd_consistency_check,
};

/* Called on module loading. Is mandatory. */
module_init(sbdd_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_exit);

/* Operations to check/reset consistency of the "stripe" */
module_param_cb(consistency, &sbdd_consistency_ops, NULL, S_IRUGO | S_IWUSR);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Driver");
