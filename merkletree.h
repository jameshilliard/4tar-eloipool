#ifndef MERKLETREE_H
#define MERKLETREE_H

#include <vector>
#include <boost/variant.hpp>
#include "tweaks.h"

namespace bitcoin {
	namespace txn {
		class Txn;
	};
};

class MerkleTree {
public:
	typedef boost::variant<bytes_t, bitcoin::txn::Txn> data_item_t;
	typedef std::vector<data_item_t> data_vec_t;
	
	MerkleTree(data_vec_t data, bool detailed = false);
	template <typename T>
	MerkleTree(std::vector<T> datain, bool detailed = false) : detail(NULL) {
		data_vec_t tmp;
		for (auto it = datain.begin(); it != datain.end(); ++it)
			tmp.push_back(*it);
		data = tmp;
		recalculate(detailed);
	};
	void _init(data_vec_t data);
	
	void recalculate(bool detailed = false);
	bytes_t withFirst(data_item_t);
	bytes_t merkleRoot();
	
	data_vec_t data;
	data_vec_t *detail;
	std::vector<bytes_t> _steps;
};

#endif
