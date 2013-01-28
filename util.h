#ifndef UTIL_H
#define UTIL_H

#include <time.h>
#include <functional>
#include <map>
#include <queue>
#include <tuple>

extern bytes_t dblsha(bytes_t);

#define tryErr(e, ...)  do { try { __VA_ARGS__ } catch (e) {} } while(0)

class ScheduleDict {
public:
	ScheduleDict();
	
	time_t nextTime();
	std::function<void()> shift();
	void __setitem__(std::function<void()>&, time_t);
	time_t __getitem__(std::function<void()>&);
	void erase(std::function<void()>&);
	size_t size();
	bool empty();

private:
	typedef std::tuple<time_t, void *, std::function<void()> > pq_element_t;
	class comparer {
	public:
		bool operator() (const pq_element_t &, const pq_element_t &) const;
	};
	typedef std::priority_queue<pq_element_t, std::vector<pq_element_t>, comparer> pq_t;
	
	void _build_heap();
	
	std::map<void *, std::pair<time_t, std::function<void()> > > _dict;
	pq_t _heap;
};

#endif
