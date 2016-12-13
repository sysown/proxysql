#include "auth.h"

#include "proxysql_atomic.h"


namespace proxysql { namespace auth {

AccountDetails::AccountDetails()
	: default_hostgroup(0)
	  , max_connections(0)
	  , num_connections_used(0)
	  , use_ssl(false)
	  , schema_locked(false)
	  , transaction_persistent(false)
	  , fast_forward(false)
	  , __active(true)
	{}

Group::Group(GroupType t)
	: t_(t)
{
	spinlock_rwlock_init(&lock_);
}

void
Group::add(std::shared_ptr<AccountDetails> d) {
	spin_wrlock(&lock_);
	auto lookup = creds_.find(d->username);
	if (lookup != creds_.end()) {
		auto& old = lookup->second;
		if (old->password == d->password) {
			d->sha1_pass = old->sha1_pass;
		}
		creds_.erase(lookup->first);
	}
	creds_.insert(std::make_pair(d->username, d));
	spin_wrunlock(&lock_);
}

void
Group::del(const std::string& username) {
	spin_wrlock(&lock_);
	creds_.erase(username);
	spin_wrunlock(&lock_);
}

std::shared_ptr<const AccountDetails>
Group::lookup(const std::string& username) {
	std::shared_ptr<const AccountDetails> details;

	spin_rdlock(&lock_);
	auto lookup = creds_.find(username);
	if (lookup != creds_.end()) {
		details = lookup->second;
	}
	spin_rdunlock(&lock_);

	return details;
}

void
Group::set_SHA1(const std::string& username, void *sha_pass) {
	spin_wrlock(&lock_);
	auto lookup = creds_.find(username);
	if (lookup != creds_.end()) {
		auto& ad = lookup->second;
		if (sha_pass) {
			uint8_t *sha1_pass = static_cast<uint8_t *>(sha_pass);
			ad->sha1_pass = std::vector<uint8_t>(sha1_pass, sha1_pass + SHA_DIGEST_LENGTH);
		}
	}
	spin_wrunlock(&lock_);
}

int
Group::increase_connections(const std::string& username, int *mc) {
	int ret = 0;
	spin_wrlock(&lock_);
	auto it = creds_.find(username);
	if (it != creds_.end()) {
		auto& ad = it->second;
		ad->num_connections_used++;
		ret = ad->max_connections - ad->num_connections_used;
		if (mc) {
			*mc = ad->max_connections;
		}
	}
	spin_wrunlock(&lock_);
	return ret;
}

void
Group::decrease_connections(const std::string& username) {
	spin_wrlock(&lock_);
	auto it = creds_.find(username);
	if (it != creds_.end()) {
		auto &ad = it->second;
		if (ad->num_connections_used > 0) {
			ad->num_connections_used--;
		}
	}
	spin_wrunlock(&lock_);
}

void
Group::set_all_inactive() {
	spin_wrlock(&lock_);
	for (auto& it: creds_) {
		it.second->__active = false;
	}
	spin_wrunlock(&lock_);
}

void
Group::remove_inactives() {
	spin_wrlock(&lock_);
	for (auto it = creds_.begin(); it != creds_.end(); ) {
		if (!it->second->__active) {
			it = creds_.erase(it);
		} else {
			++it;
		}
	}
	spin_wrunlock(&lock_);
}

std::vector<std::pair<GroupType, std::shared_ptr<const AccountDetails>>>
Group::dump() {
	spin_rdlock(&lock_);

	std::vector<std::pair<GroupType, std::shared_ptr<const AccountDetails>>> items;
	for (auto& it: creds_) {
		items.push_back(std::make_pair(t_, it.second));
	}
	spin_rdunlock(&lock_);

	return items;
}


Auth::Auth() {
	for (size_t i = 0; i < groups_.size(); i++) {
		groups_[i] = std::make_shared<Group>(static_cast<GroupType>(i));
	}
}

std::vector<std::pair<GroupType, std::shared_ptr<const AccountDetails>>>
Auth::dump_all_users() {
	std::vector<std::pair<GroupType, std::shared_ptr<const AccountDetails>>> items;
	for (auto& g: groups_) {
		auto items2 = g->dump();
		items.insert(
			items.end(),
			std::make_move_iterator(items2.begin()),
			std::make_move_iterator(items2.end()));
	}

	return items;
}

void
Auth::print_version() {
	fprintf(stderr, "Standard MySQL Authentication rev. %s -- %s -- %s\n",
			MYSQL_AUTHENTICATION_VERSION, __FILE__, __TIMESTAMP__);
}

}}
