//
// Created by 1655664358@qq.com on 2020/3/25.
//

函数event_config_avoid_method(struct event_config *cfg, const char *method)分析

struct event_config_entry
{
 		struct {
				struct event_config_entry *tqe_next;
 				struct event_config_entry **tqe_prev;
		}next;
		const char *avoid_method;
}
//初始化，然后赋值操作
struct event_config_entry *entry = mm_malloc(sizeof(*entry));

//method外部传入的参数
//event_config *cfg 外部传入的参数
entry->avoid_method = mm_strdup(method)
(entry)->next.tqe_next = NULL
(entry)->next.tqe_prev = (cfg->entries)->tqh_last

//&cfg->entries

*(cfg->entries)->tqh_last = (entry);
(cfg->entries)->tqh_last = &(entry)->next.tqe_next;


struct event_config {
    struct event_configq{
     				struct event_config_entry *tqh_first;
       				struct event_config_entry **tqh_last;
    }entries;

    int n_cpus_hint;
    enum event_method_feature require_features;
    enum event_base_config_flag flags;
}



