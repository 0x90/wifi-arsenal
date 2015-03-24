/* Hugh O'Brien */

#include <linux/module.h>

static int hughnav_value = 0;
int hughnav_interval __read_mostly = HZ/30;
struct delayed_work hughnav_work;

extern int read_hughnav(void);

static void hughnav_update(struct work_struct *w)
{
	hughnav_value = read_hughnav();
	printk(KERN_ALERT "hughnav running, nav:%d\n", hughnav_value);
	schedule_delayed_work(&hughnav_work, hughnav_interval); // reschedule
}

static int start_hughnav_update_timer(void) // setup periodic reading
{
	INIT_DEFERRABLE_WORK(&hughnav_work, hughnav_update); //macro to setup the work?
	schedule_delayed_work(&hughnav_work, hughnav_interval);
	return 0;
}

static int hughnav_init(void)
{
	printk(KERN_ALERT "hughnav started, nav:%d, interval=%d\n",\
			hughnav_value, hughnav_interval);
	start_hughnav_update_timer();
	return 0;
}

static void hughnav_exit(void)
{
	cancel_delayed_work(&hughnav_work);
	printk(KERN_ALERT "hughnav exited, nav:%d\n", hughnav_value);
}

module_init(hughnav_init);
module_exit(hughnav_exit);
