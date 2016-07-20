// ------------------------------------------------------------------------------------------------
/*  Purdue CS536 - Computer Networks - Fall 2015
**  Final Project: IP Diamond
**  Kyriakos Ispoglou (ispo)
**
**   ___________  ______ _                                 _ 
**  |_   _| ___ \ |  _  (_)                               | |
**    | | | |_/ / | | | |_  __ _ _ __ ___   ___  _ __   __| |
**    | | |  __/  | | | | |/ _` | '_ ` _ \ / _ \| '_ \ / _` |
**   _| |_| |     | |/ /| | (_| | | | | | | (_) | | | | (_| |
**   \___/\_|     |___/ |_|\__,_|_| |_| |_|\___/|_| |_|\__,_|
**                                                           
**  * * * ---===== IP Diamond v1.1 =====--- * * *
**
**  ipd_krnl.c 
**
**  This is the kernel module that uses netfilter to "steal" packets directly from NIC.
**  Packets that match with a given src/dst IP address are stealed and forwarded to a
**  user process using a device driver.
**
**  The same process could be done using TUN/TAP interfaces and I think it would be better :\
*/
// ------------------------------------------------------------------------------------------------
#include <linux/init.h>                                 /* module_init/module_clear */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/device.h>                               /* for device driver */
#include <linux/cdev.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>                       /* netfilter stuff */
#include <linux/netfilter.h>
#include <linux/netdevice.h> 
#include <linux/slab.h>                                 /* kmalloc() */
#include <linux/ip.h>             
#include <linux/skbuff.h>         
#include <linux/kfifo.h>                                /* our queue */
#include <linux/mutex.h>                                /* mutexes */
#include <linux/interrupt.h>

// ------------------------------------------------------------------------------------------------
#define FIFO_SIZE           1<<19                       // allow up to 8 65KB packets
#define MAXIPLEN            65536                       // IPv4 max size is 65KB

#define ERROR_CANNOT_LOCK   0x700001                    // cannot lock mutex
#define ERROR_CANNOT_COPY   3233                        // cannot copy to userspace
#define ERROR_MEMALLOC      0x41                        // cannot allocate memory
#define ERROR_MODE_INVALID  0x45                        // invalid mode (RDONLY/RDWR)

#define MODE_UNUSED         0xe0001                     // uinf is free
#define MODE_BACK           0xe0002                     // uinf is in forward mode
#define MODE_FORTH          0xe0004                     // uinf is in backward mode

#define LOCK_STATE_UP       10                          // mutex is locked
#define LOCK_STATE_DOWN     20                          // mutex is unlocked

#define O_BACK              0x1f                        // during open(O_RDWR), f_mode is 0x1f
#define O_FORTH             0x1d                        // during open(O_RDONLY), f_mode is 0x1d


static DEFINE_MUTEX( i_rd_lock );                       // locks for read/write in input kfifo
static DEFINE_MUTEX( i_wt_lock );                       //
static DEFINE_MUTEX( o_rd_lock );                       // locks for read/write in output kfifo
static DEFINE_MUTEX( o_wt_lock );                       //


/* ------------------------------------------------------------------------
 *  localhost: 127.0.0.1   -> 0x7f000001 -> 0x0100007f
 *  xinu09   : 128.10.3.59 -> 0x800a033b -> 0x3b030a80
 * ------------------------------------------------------------------------ */
const __u32  ip_addr = /*0x6601a8c0;*/ 0x3b030a80;      // address to filter

// ------------------------------------------------------------------------------------------------
typedef unsigned char uchr_t;                           // a typedef

//
// * * * WARNING! * * *
//  We assume that a single instance of ipd_usr runs. Otherwise race conditions will start
//  partying and nothing is going to work!
//
typedef struct  {                                       /* ipd_usr information buffer */
    int             mode,                               // mode (in/out/invalid)
                    lockst;                             // lock state (up/down)
    struct mutex    lock;                               // mutual exclusion semaphore
    uchr_t          tmpbuf[ MAXIPLEN ];                 // temporary buffer to hold extracted 
                                                        // packet from queue
} uibuf_t;


/* kfifo_rec_ptr_2 because records can have length up to 65535 bytes.*/
struct kfifo_rec_ptr_2  ipktq, opktq;                   // incoming and outgoing packet queues
uibuf_t                 *back_b, *forth_b;              // global pointers of our files


// ------------------------------------------------------------------------------------------------
//                          * * * ---===== NETFILTER HOOKS =====--- * * *
//
// The first hook (hook_func_forth) is placed between OUTPUT and POSTROUTING to grab and "steals" 
// outgoing IP packets that match our rules (specific IPs in this project).
// The second hook (hook_func_back) is placed at PREROUTING chain to grab incoming IP packets that
// are destined for attacker. We apply the same rules to match packets as in the first hook.
// ------------------------------------------------------------------------------------------------
static unsigned int hook_func_forth(                      /* this is our callback function (hook) */
        const struct nf_hook_ops    *ops,
        struct sk_buff              *skb,
        const struct net_device     *in,
        const struct net_device     *out,
        int                         (*okfn)(struct sk_buff *)
) {
    struct iphdr *ip_hdr;                               // ip header
    __u16        ip_len;                                // total size of packet
    int          nadd;                                  // number of elements added in queue
    

    if( !skb || !forth_b ) return NF_ACCEPT;            // exit on NULL or if hooking not requested

    ip_hdr = (struct iphdr*) skb_network_header(skb);   // get IP packet header
    ip_len = ntohs(ip_hdr->tot_len);                    // get packet's size
    
    /* ------------------------------------------------------------------------
     *  the if() below is used to do the rule match. For this project we filter
     *  only a specific IP. However you can apply any filter you want (filter
     *  ports, ip ranges, http/ftp traffic, etc.)
     * ------------------------------------------------------------------------ */
    if( ip_hdr->daddr == ip_addr )                      // destinaton address match?
    { 
        /* rule matched */

        if( mutex_lock_interruptible(&o_wt_lock) )      // lock write mutex
            return NF_DROP;                             // error

        /* there's no need to do overflow check. kfifo will take care of that */
        nadd = kfifo_in(&opktq,(uchr_t*)ip_hdr,ip_len); // push packet to queue

        mutex_unlock(&o_wt_lock);                       // unlock write mutex


        // you can also check if semaphore is locked by checking kfifo_is_empty
        if( forth_b && forth_b->lockst == LOCK_STATE_DOWN )
            mutex_unlock(&forth_b->lock);               // release semaphore if it's down           

        printk(KERN_INFO "Outgoing packet (%d) Stolen. Queue: (n,len) = (%d,%u)\n", 
                    ip_len, nadd, kfifo_len(&opktq));   

        return NF_STOLEN;                               // don't allow packet to proceed 
    }

    return NF_ACCEPT;                                   // accept packet
}

// ------------------------------------------------------------------------------------------------
static unsigned int hook_func_back(                      /* second (hook) for incoming packets*/
        const struct nf_hook_ops    *ops,
        struct sk_buff              *skb,
        const struct net_device     *in,
        const struct net_device     *out,
        int                         (*okfn)(struct sk_buff *)
) {
    struct iphdr *ip_hdr;                               // ip header
    __u16        ip_len;                                // total size of packet
    int          nadd;                                  // number of elements added in queue
    

    if( !skb || !back_b ) return NF_ACCEPT;             // exit on NULL or if hooking not requested

    ip_hdr = (struct iphdr*) skb_network_header(skb);   // get IP packet header
    ip_len = ntohs(ip_hdr->tot_len);                    // get packet's size
    
    /* ------------------------------------------------------------------------
     * apply the same logic as in previous hook  
     * ------------------------------------------------------------------------ */
    if( ip_hdr->saddr == ip_addr )                      // source address match?
    { 
        /* rule matched */

        if( mutex_lock_interruptible(&i_wt_lock) )      // lock write mutex
            return NF_DROP;                             // error

        nadd = kfifo_in(&ipktq,(uchr_t*)ip_hdr,ip_len); // push packet to queue

        mutex_unlock(&i_wt_lock);                       // unlock write mutex
        
        if( back_b && back_b->lockst == LOCK_STATE_DOWN )
            mutex_unlock(&back_b->lock);                // unlock mutex

        printk(KERN_INFO "Incoming packet (%d) Stolen. Queue: (n,len) = (%d,%u)\n", 
                    ip_len, nadd, kfifo_len(&ipktq));

        return NF_STOLEN;                               // don't allow packet to proceed 
    }

    return NF_ACCEPT;                                   // accept packet
}

// ------------------------------------------------------------------------------------------------
// Netfilter hook values:
//      #define NF_IP_PRE_ROUTING       0
//      #define NF_IP_LOCAL_IN          1
//      #define NF_IP_FORWARD           2
//      #define NF_IP_LOCAL_OUT         3
//      #define NF_IP_POST_ROUTING      4
//      #define NF_IP_NUMHOOKS          5
//
static struct nf_hook_ops nfho_forth =                  /* set netfilter forward hook options */
{
    .hook       = hook_func_forth,                      // hook function
    .hooknum    = 3,                                    // place hook at NF_IP_LOCAL_OUT
    .pf         = PF_INET,                              // IPv4
    .priority   = NF_IP_PRI_FIRST                       // set priority
};

// ------------------------------------------------------------------------------------------------
static struct nf_hook_ops nfho_back =                   /* set netfilter backward hook options */
{
    .hook       = hook_func_back,                       // hook function
    .hooknum    = 0,                                    // place hook at NF_IP_LOCAL_PRE_ROUTING
    .pf         = PF_INET,                              // IPv4
    .priority   = NF_IP_PRI_FIRST                       // set priority
};


// ------------------------------------------------------------------------------------------------
//                          * * * ---===== DEVICE DRIVER =====--- * * *
//
// With this driver, the user mode part of ipd can call open() and then read() to get the raw IP
// packets captures by netfilter.
// ------------------------------------------------------------------------------------------------
static dev_t  devfst;                                   // first device number 
static struct cdev c_dev;                               // character device struct
static struct class *cls;                               // and device class

// ------------------------------------------------------------------------------------------------
static int ipd_open(struct inode *i, struct file *f) 
{
    uibuf_t *buf = NULL;                                // file's internal buffer


    if(!(buf = kzalloc(sizeof(uibuf_t), GFP_KERNEL)))   // alloc & zero memory
        return -ERROR_MEMALLOC;
    
    mutex_init(&buf->lock);                             // initialize mutex to 1
    
    if( mutex_lock_interruptible(&buf->lock) )          // mustex must be set to zero
        return -ERROR_CANNOT_LOCK;

    buf->lockst = LOCK_STATE_UP;                        // lock is up
    f->private_data = buf;                              // associate file with our internal data

    /* ------------------------------------------------------------------------
     * Our traffic is bidirectional. We need to either steal outgoing packets
     * from attacker's machine and forward them to level 2 relay, or to steal 
     * incoming packets from level 2 relay and send them back to attacker.
     * The first type of traffic is forward, and then second is backward. When
     * device is opened in read-only mode we steal outgoing packets, and when
     * is opened in read-write mode we steal incoming packets. This is just a
     * convention. We need that in order to be able to distinguish in read()
     * from which queue we'll read packets.
     * ------------------------------------------------------------------------ */
    switch( f->f_mode )                                 // determine mode
    {
        // --------------------------------------------------------------------
        case O_FORTH:   printk(KERN_INFO "[IP Diamond] Device opened in forward mode!\n");
                        buf->mode = MODE_FORTH;     
                        forth_b = buf;                      
                        break;
        // --------------------------------------------------------------------
        case O_BACK:    printk(KERN_INFO "[IP Diamond] Device opened in backward mode!\n");
                        buf->mode = MODE_BACK;
                        back_b = buf;
                        break;
        // --------------------------------------------------------------------
        default:        printk(KERN_INFO "[IP Diamond] [Fatal] Unknown device mode!\n");
                        kfree(buf);                     // release memory           
                        return -ERROR_MODE_INVALID;     // set error code
        // --------------------------------------------------------------------
    }

    return 0;                                           // sucess
}

// ------------------------------------------------------------------------------------------------
static int ipd_close(struct inode *i, struct file *f) 
{
    printk(KERN_INFO "[IP Diamond] Device closed.\n");

    switch( f->f_mode ) {                               // don't have stale pointers
        case O_FORTH: forth_b = NULL; break;        
        case O_BACK:  back_b  = NULL;   
    }

    kfree(f->private_data);                             // release internal buffer

    return 0;                                           // always return sucess
}

// ------------------------------------------------------------------------------------------------
static ssize_t ipd_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    
    /* this should never be called */

    printk(KERN_INFO "[IP Diamond] Write to device?\n");    
    return -1;                                          // always return error
}

// ------------------------------------------------------------------------------------------------
static ssize_t ipd_read(struct file *f, char __user *usrbuf, size_t len, loff_t *off)
{
    uibuf_t *buf = f->private_data;                     // get file's internal buffer
    int     osz = 10;                                   // dequeued object's size 


    /* ------------------------------------------------------------------------
     * based on the open mode, select packet from the appropriate queue
     * ------------------------------------------------------------------------ */
    if( buf->mode == MODE_FORTH )
    {
        printk(KERN_INFO "[IP Diamond] Packet request from forward direction\n");
    
        if( kfifo_is_empty(&opktq) )                    // is output queue empty?
        {
            buf->lockst = LOCK_STATE_DOWN;              // mutex locked
            if( mutex_lock_interruptible(&buf->lock) )  // if so, block on mutex
                return -ERROR_CANNOT_LOCK;              // error on failure
        }

        /* queue is not empty here. Grab a packet and send it to user mode */

        // Note that if packet is length is >len (user's buffer size) kfifo_out will remove 
        // the whole packet and will discard the bytes from the packet that don't fit in buf.
        if( mutex_lock_interruptible(&o_rd_lock) )      // lock read mutex
            return -ERROR_CANNOT_LOCK;

        osz = kfifo_out(&opktq, buf->tmpbuf, len);      // get a packet from output queue   

        mutex_unlock(&o_rd_lock);                       // unlock read mutex
    }

    else if( buf->mode == MODE_BACK )
    {
        printk(KERN_INFO "[IP Diamond] Packet request from backward direction\n");

        if( kfifo_is_empty(&ipktq) )                    // is output queue empty?
        {
            buf->lockst = LOCK_STATE_DOWN;              // mutex locked
            if( mutex_lock_interruptible(&buf->lock) )  // if so, block on mutex
                return -ERROR_CANNOT_LOCK;              // error on failure
        }
        
        if( mutex_lock_interruptible(&i_rd_lock) )      // lock read mutex
            return -ERROR_CANNOT_LOCK;

        osz = kfifo_out(&ipktq, buf->tmpbuf, len);      // get a packet from INPUT queue

        mutex_unlock(&i_rd_lock);                       // unlock read mutex    
    }
    
    else return -ERROR_MODE_INVALID;                    // otherwise failure


    if( copy_to_user(usrbuf, buf->tmpbuf, osz) )        // copy to userspace
        return -ERROR_CANNOT_COPY;                      // cannot copy

    return osz;                                         // return bytes read
}

// ------------------------------------------------------------------------------------------------
static struct file_operations ipd_ops = {               /* set device API */
    .owner   = THIS_MODULE,
    .open    = ipd_open,
    .release = ipd_close,
    .read    = ipd_read,
    .write   = ipd_write
};


// ------------------------------------------------------------------------------------------------
//                         * * * ---===== MODULE INIT/EXIT =====--- * * *
//
// Module entry and exit points.
// ------------------------------------------------------------------------------------------------
static int __init init_nf(void)                         /* module's entry point */
{

    printk(KERN_INFO "---===== ------------------------------------------ =====---\n");
    printk(KERN_INFO "---=====   PURDUE Univ. CS536 - Computer Networks   =====---\n");
    printk(KERN_INFO "---=====       Final Project: IP Diamond v1.1       =====---\n");
    printk(KERN_INFO "---=====                                            =====---\n");
    printk(KERN_INFO "---=====                                     -ispo  =====---\n");
    printk(KERN_INFO "---===== ------------------------------------------ =====---\n");
    printk(KERN_INFO "[IP Diamond] ipd_krnl started...\n");


    /* ------------------------------------------------------------------------
     *  initialize our packet buffer (kfifo queue)
     * ------------------------------------------------------------------------ */
    if( kfifo_alloc(&opktq, FIFO_SIZE, GFP_KERNEL) ||
        kfifo_alloc(&ipktq, FIFO_SIZE, GFP_KERNEL) ) {
        printk(KERN_INFO "[IP Diamond] kFIFO allocation error.");
        return -1;
    }

    kfifo_reset(&opktq);                                // clear queues
    kfifo_reset(&ipktq);                                //


    printk(KERN_INFO "[IP Diamond] QUEUE LEN: %d - %d\n", kfifo_len(&opktq), kfifo_len(&ipktq));


    /* ------------------------------------------------------------------------
     *  register netfilter hook functions
     * ------------------------------------------------------------------------ */
    nf_register_hook( &nfho_back );                     // register netfilter hooks
    nf_register_hook( &nfho_forth );
    printk(KERN_INFO "[IP Diamond] Netfilter hooks installed.\n");

    /* ------------------------------------------------------------------------
     *  initialize our device driver, which will be the channel to send packets 
     *  to userspace.
     * ------------------------------------------------------------------------ */
    if( alloc_chrdev_region(&devfst, 0, 1, "ip_diamond") < 0 )
        return -1;                                      // register device number
  
    if( (cls = class_create(THIS_MODULE, "ip_diamond")) == NULL ) {
        printk(KERN_INFO "[IP Diamond] [Fatal] Cannot create class!\n");
        unregister_chrdev_region(devfst, 1);            // unregister device number
        return -1;                                      // failure
    }

    /* creates the actual device and register it with sysfs  */
    if( device_create(cls, NULL, devfst, NULL, "ip_diamond") == NULL ) {
        printk(KERN_INFO "[IP Diamond] [Fatal] Caninot create device!\n");
        class_destroy( cls );                           // destruct class
        return -1;                                      // failure);
    }

    cdev_init(&c_dev, &ipd_ops);                        // initialize cdev structure 

    if( cdev_add(&c_dev, devfst, 1) == -1 ) {           // add char device to system
        printk(KERN_INFO "[IP Diamond] [Fatal] Cannot add device to the system!\n");
        device_destroy(cls, devfst);                    // remove device
        class_destroy( cls );                           // destruct class
        unregister_chrdev_region(devfst, 1);
        return -1;                                      // failure
    }

    printk(KERN_INFO "[IP Diamond] Device driver ok.");

    return 0;                                           // return sucess
}

// ------------------------------------------------------------------------------------------------
static void __exit exit_nf( void )                      /* module's exit point */
{
    printk(KERN_INFO "[IP Diamond] Module stopped!\n");


    kfifo_free(&opktq);                                 // release packet queues
    kfifo_free(&ipktq);

    nf_unregister_hook(&nfho_back);                     // unregister netfilter hooks
    nf_unregister_hook(&nfho_forth);

    cdev_del(&c_dev);                                   // remove char device from the system 
    device_destroy(cls, devfst);                        // remove device
    class_destroy( cls );                               // destruct class
    unregister_chrdev_region(devfst, 1);                // unregister device number
    

    printk(KERN_INFO "[IP Diamond] Everything is unregistered. Bye bye! :)");
}

// ------------------------------------------------------------------------------------------------
module_init(init_nf);                                   // set entry routine
module_exit(exit_nf);                                   // cleanup routine

MODULE_LICENSE("GPL");                                  // leave GPL for now
MODULE_DESCRIPTION("IP Diamond");                       // proj name
MODULE_AUTHOR("ispo");                                  // I wrote it!
// ------------------------------------------------------------------------------------------------
