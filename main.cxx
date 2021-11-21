/* $Header$ */

/// \file GpsServer main file.
/// Compile using __USE_BSD.
///
/// See \c gps_server.doc for complete specification.

#ifdef WIN32
#pragma warning(disable:4786) 
#include <winsock2.h>	// struct timeval.
#endif

#include <vector>	// std::vector
#include <string>	// std::string
#include <list>		// std::list

#include <stdio.h>	// printf, sprintf
#include <stdarg.h>	// varargs.

#include <event.h>	// libevent.
#include <sys/types.h>	// DIR?
#include <sys/stat.h>	// stat
#include <unistd.h>	// ??
#include <dirent.h>	// opendir..

#include <utils/mysockets.h>		// open_server_socket
#include <utils/util.h>			// SimpleConfig, Error.
#include <utils/TracerStorage.h>	// TSPacketAssembler
#include <utils/MD5.h>			// Digest algorithm "MD-5".

using namespace utils;

static const char*	FILENAME_CONFIGURATION	= "GpsServer.ini";
static const int	SERVER_PORT		= 2006;
static const char*	EVENTNAME_CHEATER	= "GPSViewer.massaraksh";
static const char*	EVENTNAME_IDENTIFY	= "GPSViewer.identify";
static const char*	EVENTNAME_AUTH		= "GpsViewer";
static const char*	EVENTNAME_SLAVELIST	= "GPSViewer.slaves";
static const char*	EVENTNAME_SELECTSLAVE	= "GPSViewer.selectslave";
static const char*	EVENTNAME_SLAVECHANGE	= "GPSViewer.slavechange";
static const char*	EVENTNAME_PING		= "PING";
// static const char*	DIRNAME_DATA		= "data";
static const int	SCANCOUNT_TRUST_LEVEL	= 3; // Scans of equal results required to be trusted.

typedef enum {
	EVENTTYPE_UNKNOWN,
	EVENTTYPE_CHEATER,
	EVENTTYPE_IDENTIFY,
	EVENTTYPE_AUTH,
	EVENTTYPE_SLAVELIST,
	EVENTTYPE_SELECTSLAVE,
	EVENTTYPE_SLAVECHANGE
} EVENTTYPE;

/// Timeout, in seconds.
#define	MAX_IDLE_TICKS	20

/// Ping every N ticks.
#define	PING_TICKS	5

/*****************************************************************************/
/// Parse event.
/// \param[in]	event	Event to be parsed.
/// \param[out]	args	Arguments to the event.
/// \return		Type of event.
static EVENTTYPE
parse_event(	const TS_Event&			event,
		std::vector<std::string>&	args)
{
	args.resize(0);

	/// Split event by whitespace.
	std::vector<std::string>	v;
	split(event.data, " ", v);
	if (v.size() == 0) {
		return EVENTTYPE_UNKNOWN;
	}

	// Copy arguments.
	for (unsigned int i=1; i<v.size(); ++i) {
		args.push_back(v[i]);
	}

	const std::string&	name = v[0];
	if (name == EVENTNAME_CHEATER)
		return EVENTTYPE_CHEATER;
	if (name == EVENTNAME_IDENTIFY)
		return EVENTTYPE_IDENTIFY;
	if (name == EVENTNAME_AUTH)
		return EVENTTYPE_AUTH;
	if (name == EVENTNAME_SLAVELIST)
		return EVENTTYPE_SLAVELIST;
	if (name == EVENTNAME_SELECTSLAVE)
		return EVENTTYPE_SELECTSLAVE;
	if (name == EVENTNAME_SLAVECHANGE)
		return EVENTTYPE_SLAVECHANGE;
	return EVENTTYPE_UNKNOWN;
}

/*****************************************************************************/
/// Build event of given type.
static std::string
build_event(	const EVENTTYPE			event_type,
		const char*			fmt, ...)
{
	std::string	r;

	// Make name.
	switch (event_type) {
	case EVENTTYPE_CHEATER:
		r = EVENTNAME_CHEATER;
		break;
	case EVENTTYPE_IDENTIFY:
		r = EVENTNAME_IDENTIFY;
		break;
	case EVENTTYPE_AUTH:
		r = EVENTNAME_AUTH;
		break;
	case EVENTTYPE_SLAVELIST:
		r = EVENTNAME_SLAVELIST;
		break;
	case EVENTTYPE_SELECTSLAVE:
		r = EVENTNAME_SELECTSLAVE;
		break;
	case EVENTTYPE_SLAVECHANGE:
		r = EVENTNAME_SLAVECHANGE;
		break;
	default:
		assert(0);
		throw Error("Internal error.");
	}

	// Append arguments.
	char	xbuf[1024] = { 0 };
	va_list	ap;
	va_start(ap, fmt);
	vsprintf(xbuf, fmt, ap);
	va_end(ap);
	if (strlen(xbuf) > 0) {
		r += ' ';
		r += xbuf;
	}

	// Over :)
	return r;
}

/*****************************************************************************/
/// Slave.
typedef struct {
	std::string	id;
	std::string	name;
} SLAVE_CONFIG;


/// A mode client might have...
typedef enum {
	CLIENTMODE_UNIDENTIFIED,	///< Yet to receive identification packet.
	CLIENTMODE_MASTER,		///< Identified as master.
	CLIENTMODE_SLAVE,		///< Identified as slave.
	CLIENTMODE_REJECTED		///< Rejected, no longer talking to.
} CLIENTMODE;

class GpsServer;

/// Client info.
class TCP_CLIENT {
public:
	unsigned int			fd;	///< Client socket.
	struct bufferevent*		event;	///< Buffered events.
	GpsServer*			server;	///< Points back to server.
	TSPacketAssembler		packet_assembler;	///< Assembles packets read from \c fd.
	CLIENTMODE			mode;	///< Client mode.
	std::string			slave_name;	///< Name of the slave. Used when \c slave==0.
	std::list<TCP_CLIENT*>		masters;///< Masters watching this client.
	std::string			id;	///< ID of the client. Valid only if identified.
	std::string			name;	///< Name of the client. Valid only if identified.
	int				idle_ticks;	///< Number of idle ticks.
}; // struct TCP_CLIENT.

#if 0
/***************************************************************/
/// String representation of \c addr.
static std::string
connection_name_of_sockaddr(	const struct sockaddr_in&	addr,
				std::string&			hostname)
{
	std::string	r;
	
	// Detect hostname, if possible.
	hostname.resize(0);
	const struct hostent*	he = gethostbyaddr(&addr.sin_addr, sizeof(addr.sin_addr), AF_INET);
	if (he == 0) {
		const char*	ipname = inet_ntoa(addr.sin_addr);
		if (ipname == 0) {
			hostname = "Undetected";
		} else {
			hostname = ipname;
		}
	} else {
		hostname = he->h_name;
	}

	// Form return string.
	char		xbuf[1024];
	r += hostname;
	r += ":";
	sprintf(xbuf, "%d", addr.sin_port);
	r += xbuf;

	// yeah.
	return r;
}
#endif

/*****************************************************************************/
/*****************************************************************************/
/// Server main.
class GpsServer {
private:
	std::vector<std::string>	config_masters_;		///< Configured masters.
	unsigned int			config_concurrent_masters_;	///< maximum number of concurrent masters.
	std::vector<SLAVE_CONFIG>	config_slaves_;			///< Slaves which are allowed to work with us :)
	std::string			config_dirname_data_;		///< Data directory.

	struct event_base*		evb_;
	unsigned int			listening_socket_;		///< Listening TCP/IP socket.
	struct event			listening_socket_event_;	///< TCP port "listen" events.
	struct timeval			timer_period_;			///< Timer period, every 5 minutes.
	struct event			timer_event_;			///< Timer event.
	unsigned int			timer_count60_;			///< Count 0..59.
	unsigned int			timer_countping_;		///< Count ping ticks.

	std::list<TCP_CLIENT*>		tcp_clients_;			///< List of clients :)
	std::string			tcp_read_buffer_;		///< Temporary buffer for TCP reads.
	utils::TracerWriter		tcp_writer_;			///< Global packet serializer.
	ts_buffer_t			tcp_write_buffer_;		///< Global write buffer.
public:
	/*****************************************************************************/
	/// Log a message preceded by time in format "HHMMSS".
	static void
	log(			const char*		fmt, ...)
	{
		my_time	rtime;
		get_my_time(rtime);
		printf("%02d%02d%02d: ", rtime.hour, rtime.minute, rtime.second);

		va_list	ap;
		va_start(ap, fmt);
		vfprintf(stdout, fmt, ap);
		va_end(ap);
		printf("\n");
		fflush(stdout);
	}
private:

	/*****************************************************************************/
	/// Compose event reporting list of slaves...
	std::string
	build_slavelist_event()
	{
		std::string			r(EVENTNAME_SLAVELIST);
		std::vector<std::string>	slaves_so_far;

		for (std::list<TCP_CLIENT*>::const_iterator it=tcp_clients_.begin(); it!=tcp_clients_.end(); ++it) {
			const TCP_CLIENT*	tcp_client = *it;
			if (tcp_client->mode == CLIENTMODE_SLAVE) {
				bool	fresh = true;
				for (unsigned int sofarIndex=0; sofarIndex<slaves_so_far.size(); ++sofarIndex) {
					if (slaves_so_far[sofarIndex] == tcp_client->name) {
						fresh = false;
						break;
					}
				}
				if (fresh) {
					r += " ";
					r += tcp_client->name;
					slaves_so_far.push_back(tcp_client->name);
				}
			}
		}
		return r;
	}

	/*****************************************************************************/
	/// Send event to given client.
	void
	send_event(		TCP_CLIENT*		tcp_client,
				const std::string&	event)
	{
		tcp_write_buffer_.clear();
		tcp_writer_.writeEvent(event.c_str(), tcp_write_buffer_);
		bufferevent_write(tcp_client->event, &tcp_write_buffer_[0], tcp_write_buffer_.size());
	}

	/*****************************************************************************/
	/// Send event to the list of clients filtered by CLIENTMODE_MASTER.
	void
	send_event(		const std::list<TCP_CLIENT*>&		tcp_clients,
				const std::string&			event)
	{
		for (std::list<TCP_CLIENT*>::const_iterator it=tcp_clients.begin(); it!=tcp_clients.end(); ++it) {
			TCP_CLIENT*	tcp_client = *it;
			if (tcp_client->mode == CLIENTMODE_MASTER) {
				send_event(tcp_client, event);
			}
		}
	}


	/***************************************************************/
	/// Send buffer contents to all TCP/IP clients, filtered by
	/// CLIENTMODE_MASTER || CLIENTMODE_SLAVE.
	static void
	send_buffer_to_all(		const std::list<TCP_CLIENT*>&	tcp_clients,
					std::vector<unsigned char>&	buffer)
	{
		if (buffer.size()==0)
			return;

		for (std::list<TCP_CLIENT*>::const_iterator it=tcp_clients.begin(); it!=tcp_clients.end(); ++it) {
			TCP_CLIENT*	tcp_client = *it;
			if (tcp_client->mode == CLIENTMODE_MASTER || tcp_client->mode==CLIENTMODE_SLAVE) {
				bufferevent_write(tcp_client->event, &buffer[0], buffer.size());
			}
		}
	}

	/***************************************************************/
	/// Remove us from the watchlist(s), if any.
	void
	stop_broadcast_to(	TCP_CLIENT*		tcp_client)
	{
		for (std::list<TCP_CLIENT*>::const_iterator it=tcp_clients_.begin(); it!=tcp_clients_.end(); ++it) {
			TCP_CLIENT*	slave = *it;
			if (slave->mode == CLIENTMODE_SLAVE) {
				slave->masters.remove(tcp_client);
			}
		}
	}

	/***************************************************************/
	/// Shutdown and delete TCP client.
	void
	kill_tcp_client(	TCP_CLIENT*&		tcp_client,
				const char*		reason)
	{
		log("Shutting down client 0x%x, name %s (id: %s). Reason: %s", tcp_client->fd, tcp_client->name.c_str(), tcp_client->id.c_str(), reason);
		// Shutdown events.
		bufferevent_disable(tcp_client->event, EV_READ|EV_WRITE);
		bufferevent_free(tcp_client->event);
		tcp_client->event = 0;

		// Close socket.
		close_socket(tcp_client->fd);
		tcp_client->fd = 0;

		// Remove client from the chain...
		tcp_clients_.remove(tcp_client);

		switch (tcp_client->mode) {
		case CLIENTMODE_SLAVE:
			// Notify our masters.
			send_event(tcp_client->masters, build_event(EVENTTYPE_SLAVECHANGE, "offline"));

			// Notify everybody on the list about changes in the slave list.
			send_event(tcp_clients_, build_slavelist_event());
			break;
		case CLIENTMODE_MASTER:
			stop_broadcast_to(tcp_client);
		default:
			// pass
			break;
		}
		xdelete(tcp_client);
	}

	/*****************************************************************************/
	class PUSHFILE_DATA {
	public:
		PUSHFILE_DATA()
		{
		}
		PUSHFILE_DATA(	const std::string&	_filename,
				const long_long_t	_filesize,
				const time_t		_mtime)
		:	filename(_filename)
			,filesize(_filesize)
			,mtime(_mtime)
			,scan_count_equal(0)
			,data_valid(false)
			,scan_mark(true)
		{
		}

		std::string		filename;		///< Name of the file, without leading \c dirname_data_.
		long_long_t		filesize;		///< Length of the file.
		time_t			mtime;			///< Modification time.
		unsigned int		scan_count_equal;	///< Number of scans resulted in equal file sizes.
		bool			data_valid;		///< Are \c data and \c data_digest valid?
		std::vector<char>	data;			///< File data.
		unsigned char		data_digest[16];	///< MD5 digest of the file data.
		bool			scan_mark;		///< Scan mark.
	}; // class PUSHFILE_DATA.

	typedef std::list<PUSHFILE_DATA*>	Pushfiles;
	Pushfiles				pushfile_data_;	/* Files to be pushed. */

	/*****************************************************************************/
	/// Remove \c pushfile from \c pushfile_data_ and delete it, to.
	void
	remove_pushfile(	PUSHFILE_DATA*	pushfile)
	{
		pushfile_data_.remove(pushfile);
		delete pushfile;
	}

	/*****************************************************************************/
	/// Allocate new pushfile and push it into front of \c pushfile_data_.
	PUSHFILE_DATA*
	add_pushfile()
	{
		PUSHFILE_DATA*	r = new PUSHFILE_DATA;
		pushfile_data_.push_front(r);
		return r;
	}

	/*****************************************************************************/
	/**
	Load pushfile contents and mark it valid.
	*/
	void
	load_pushfile(		PUSHFILE_DATA*	pushfile)
	{
		try {
			// 1. Read file.
			{
				const std::string	filename(dircat(config_dirname_data_, pushfile->filename));
				hxio::IO	f;
				f.open(filename, "rb");
				pushfile->data.resize(pushfile->filesize);
				f.read(reinterpret_cast<unsigned char*>(&pushfile->data[0]), pushfile->data.size());
				f.close();
			}
			// 2. Calculate checksum.
			{
				md5_state_t	ms;
				md5_init(&ms);
				md5_append(&ms, reinterpret_cast<unsigned char*>(&pushfile->data[0]), pushfile->data.size());
				md5_finish(&ms, pushfile->data_digest);
			}
			// 3. Mark it valid.
			pushfile->data_valid = true;
			log("Pushfile %s loaded, %d bytes.", pushfile->filename.c_str(), pushfile->filesize);
		} catch (const std::exception& e) {
			log("Failed to load pushfile %s. Error: %s.", pushfile->filename.c_str(), e.what());
			pushfile->data_valid = false;
			pushfile->scan_count_equal = 0;
		}
	}

	/*****************************************************************************/

	/*****************************************************************************/
	/// Scan datadir and report findings.
	void
	scan_datadir()
	{
#if 0
		log("scan_datadir");

		DIR*	datadir = opendir(config_dirname_data_.c_str());
		if (datadir == 0) {
			log("Failed to scan dir %s: %d", config_dirname_data_.c_str(), errno);
			return;
		}

		// Mark all files as not scanned.
		{
			for (Pushfiles::iterator it=pushfile_data_.begin(); it!=pushfile_data_.end(); ++it) {
				(*it)->scan_mark = false;
			}
		}

		// Scan.
		struct dirent*	direntry = 0;
		while ((direntry = readdir(datadir)) != 0) {
			// Scrap some dirs really fast.
			if (strcmp(direntry->d_name, ".") == 0 || strcmp(direntry->d_name, "..")==0)
				continue;
			const std::string	filename(direntry->d_name);
			std::string		full_path(config_dirname_data_);
			full_path += "/";
			full_path += filename;

			// Stat the file and check it.
			struct stat	stbuf = { 0 };
			if (stat(full_path.c_str(), &stbuf) == -1) {
				log("Failed to stat file %s, errno:%d", full_path.c_str(), errno);
				continue;
			}
			if (!S_ISREG(stbuf.st_mode)) {
				log("File %s is not a regular file.\n", full_path.c_str());
				continue;
			}

			// Find it by filename.
			PUSHFILE_DATA*		file_data = 0;
			for (Pushfiles::iterator it=pushfile_data_.begin(); it!=pushfile_data_.end(); ++it) {
				if ((*it)->filename == direntry->d_name) {
					file_data = *it;
					break;
				}
			}
			if (file_data == 0) {
				// New dude.
				pushfile_data_.push_front(new PUSHFILE_DATA(direntry->d_name, stbuf.st_size, stbuf.st_mtime));
			} else {
				// Old dude, check if it has been refreshened.
				file_data->scan_mark = true;
				if (file_data->filesize==direntry->st_size && file_data->mtime==stbuf.st_mtime) {
					if (file_data->scan_count_equal < SCANCOUNT_TRUST_LEVEL) {
						++(file_data->scan_count_equal);
						if (file_data->scan_count_equal >= SCANCOUNT_TRUST_LEVEL) {
							// Yeah, load contents.
							load_pushfile(file_data);
						}
					}
				} else {
					unload_pushfile(file_data);
				}
			}
		}

		// Remove unmarked files, if any.
		{
			Pushfiles		files_to_remove;
			Pushfiles::iterator	it;
			for (it=pushfile_data_.begin(); it!=pushfile_data_.end(); ++it) {
				if (!it->scan_mark) {
					files_to-remove.push_front(it);
				}
			}

			for (it=files_to_remove.begin(); it!=files_to_remove.end(); ++it) {
				remove_pushfile(it);
			}
		}

		log("scan_datadir finished.");
#endif
	}

	/*****************************************************************************/
	/// Timer passed...
	static void
	timer_handler(	int			fd,
			short			event,
			void*			_self)
	{
		GpsServer*		server = reinterpret_cast<GpsServer*>(_self);
		std::list<TCP_CLIENT*>	clients_to_kill;

		// 1. Report clients...
		if (server->timer_count60_ == 0) {
			server->scan_datadir();
		}
		if (++(server->timer_count60_) >= 60) {
			server->timer_count60_ = 0;
			log("1-minute timer: .");
			for (std::list<TCP_CLIENT*>::const_iterator it=server->tcp_clients_.begin(); it!=server->tcp_clients_.end(); ++it) {
				TCP_CLIENT*	tcp_client = *it;
				switch (tcp_client->mode) {
				case CLIENTMODE_SLAVE:
					log("Slave %s (id: %s), watched by %d masters. Idle %d ticks.", tcp_client->name.c_str(), tcp_client->id.c_str(), tcp_client->masters.size(), tcp_client->idle_ticks);
					break;
				case CLIENTMODE_MASTER:
					log("Master %s (id: %s), watching %s. Idle %d ticks.", tcp_client->name.c_str(), tcp_client->id.c_str(), tcp_client->slave_name.c_str(), tcp_client->idle_ticks);
					break;
				case CLIENTMODE_UNIDENTIFIED:
					log("Unidentified 0x%x. Idle %d ticks.", tcp_client->fd, tcp_client->idle_ticks);
					break;
				case CLIENTMODE_REJECTED:
					log("Rejected 0x%x. Idle %d ticks.", tcp_client->fd, tcp_client->idle_ticks);
					break;
				}
			}
		}

		// 2. Ping clients, if possible.
		if (++(server->timer_countping_) >= PING_TICKS) {
			server->timer_countping_ = 0;
			server->tcp_write_buffer_.clear();
			server->tcp_writer_.writeEvent(EVENTNAME_PING, server->tcp_write_buffer_);
			send_buffer_to_all(server->tcp_clients_, server->tcp_write_buffer_);
		}

		// 2. Kill idle clients.
		{
			// Find idle clients....
			for (std::list<TCP_CLIENT*>::const_iterator it=server->tcp_clients_.begin(); it!=server->tcp_clients_.end(); ++it) {
				TCP_CLIENT*	tcp_client = *it;
				++tcp_client->idle_ticks;
				if (tcp_client->idle_ticks >= MAX_IDLE_TICKS) {
					clients_to_kill.push_front(tcp_client);
				}
			}

			for (std::list<TCP_CLIENT*>::iterator it=clients_to_kill.begin(); it!=clients_to_kill.end(); ++it) {
				server->kill_tcp_client(*it, "No activity.");
			}
		}

		// 3. Fire again.
		evtimer_add(&server->timer_event_, &server->timer_period_);
	}

	/***************************************************************/
	static void
	tcp_client_read_handler(struct bufferevent*	event,
				void*			_tcp_client)
	{
		TCP_CLIENT*	tcp_client = reinterpret_cast<TCP_CLIENT*>(_tcp_client);
		GpsServer*	server = tcp_client->server;
		std::string&	buffer = server->tcp_read_buffer_;
		TSPacket	packet;

		// Reset idle activity counter.
		tcp_client->idle_ticks = 0;

		// printf("TCP client read event.\n");

		// Read from buffer.
		int	so_far = 0;

		for (;;) {
			if (((int)(buffer.size())) == so_far)
				buffer.resize(so_far<=0 ? 1024 : 2*so_far);
			int	this_round = bufferevent_read(event, &buffer[so_far], buffer.size() - so_far);
			if (this_round <= 0)
				break;
			so_far += this_round;
		}

		if (so_far == 0) {
			server->kill_tcp_client(tcp_client, "TCP End-of-stream.");
			return;
		}

		// printf("Read %d bytes into buffer.\n", so_far);
		buffer.resize(so_far);
		tcp_client->packet_assembler.feed(buffer);
		std::vector<std::string>	args;
		std::vector<unsigned char>	write_buffer;
		bool				kill_self = false;

		// Handle packets...
		for (;tcp_client->packet_assembler.pop(packet); packet.close()) {
			switch (tcp_client->mode) {

			case CLIENTMODE_UNIDENTIFIED:
				// accept auth packets.
				if ((packet.type==TS_EVENT) && (parse_event(*packet.event, args)==EVENTTYPE_AUTH)) {
					if (args.size() >= 2) {
						if (args[1] == "BigBrother") {
							if (args.size() >= 4) {
								// Big brother trying to Watch...
								const std::string&	computer_id = args[2];
								const std::string&	client_id = args[3];
								for (unsigned int i=0; i<server->config_masters_.size(); ++i) {
									if (server->config_masters_[i] == client_id) {
										tcp_client->mode = CLIENTMODE_MASTER;
										tcp_client->id = computer_id;
										tcp_client->name = client_id;
										break;
									}
								}
							}
						} else {
							// Any configured worker bee?
							const std::string&	computer_id = args[1];
							for (unsigned int i=0; i<server->config_slaves_.size(); ++i) {
								const SLAVE_CONFIG&	slave_config = server->config_slaves_[i];
								if (slave_config.id == computer_id) {
									tcp_client->mode = CLIENTMODE_SLAVE;
									tcp_client->id = computer_id;
									tcp_client->name = slave_config.name;
								}
							}
						}
					}
					// do the needful.
					switch (tcp_client->mode) {
					case CLIENTMODE_UNIDENTIFIED:
						log("Authentication failed for: %s", packet.event->data.c_str());
						break;
					case CLIENTMODE_MASTER:
						// send us The List.
						log("Master %s (id: %s) connected.", tcp_client->name.c_str(), tcp_client->id.c_str());
						server->send_event(tcp_client, server->build_slavelist_event());
						break;
					case CLIENTMODE_SLAVE:
						log("Slave %s (id: %s) connected.", tcp_client->name.c_str(), tcp_client->id.c_str());
						// 1. Check if anybody has been looking for us.
						for (std::list<TCP_CLIENT*>::const_iterator it=server->tcp_clients_.begin(); it!=server->tcp_clients_.end(); ++it) {
							TCP_CLIENT*	master = *it;
							if (master->mode == CLIENTMODE_MASTER && master->slave_name==tcp_client->name) {
								tcp_client->masters.push_front(master);
								server->send_event(tcp_client, build_event(EVENTTYPE_SLAVECHANGE, "%s", tcp_client->name.c_str()));
								log("Master %s is watching %s", master->name.c_str(), tcp_client->name.c_str());
							}
						}
						server->send_event(server->tcp_clients_, server->build_slavelist_event());
						break;
					default:
						assert(0);
						throw Error("Internal error.");
					}
				}
				break;

			case CLIENTMODE_MASTER:
				// accept slavery queries and such.
				if ((packet.type==TS_EVENT)&& (parse_event(*packet.event, args)==EVENTTYPE_SELECTSLAVE)) {
					bool	got_slave = false; // it is assumed that it will succeed...
					if (args.size()>0) {
						server->stop_broadcast_to(tcp_client);

						// select new slave (either one or many), duh :)
						for (std::list<TCP_CLIENT*>::const_iterator it=server->tcp_clients_.begin(); it!=server->tcp_clients_.end(); ++it) {
							TCP_CLIENT*	slave = *it;
							if (slave->mode == CLIENTMODE_SLAVE && slave->name==args[0]) {
								slave->masters.push_front(tcp_client);
								server->send_event(tcp_client, build_event(EVENTTYPE_SLAVECHANGE, "%s", slave->name.c_str()));
								tcp_client->slave_name = args[0];
								log("Master %s is watching %s", tcp_client->name.c_str(), slave->name.c_str());
								got_slave = true;
								// may be there are many slaves...
							}
						}

					}
					if (!got_slave) {
						log("Oops, failed to identify slave according to command %s", packet.event->data.c_str());
					}
				}
				break;

			case CLIENTMODE_SLAVE:
				// forward some known TS_Events and TS_GpsPositions.
				write_buffer.resize(0);
				switch (packet.type) {
				case TS_EVENT:
					if (packet.event->data != EVENTNAME_PING) {
						server->tcp_writer_.writeEvent(packet.event->data.c_str(), write_buffer);
					}
					break;
				case TS_GPS_POSITION:
					server->tcp_writer_.writeGpsPosition(*packet.gps_position, write_buffer);
					break;
				default:
					log("Not forwarding packet type %d", packet.type);
				}
				server->send_buffer_to_all(tcp_client->masters, write_buffer);
				break;

			case CLIENTMODE_REJECTED:
				kill_self = true;
				break;
			default:
				assert(false);
			}
		}
		if (kill_self) {
			server->kill_tcp_client(tcp_client, "Rejected.");
		}
	}

	/***************************************************************/
	static void
	tcp_client_write_handler(struct bufferevent*	event,
				void*			_tcp_client)
	{
		TCP_CLIENT*	tcp_client = reinterpret_cast<TCP_CLIENT*>(_tcp_client);
		GpsServer*	server = tcp_client->server;
		// printf("TCP client write event.\n");

		// Pass.

		(void)server;
	}

	/***************************************************************/
	static void
	tcp_client_error_handler(struct bufferevent*	event,
				short			what,
				void*			_tcp_client)
	{
		TCP_CLIENT*	tcp_client = reinterpret_cast<TCP_CLIENT*>(_tcp_client);
		GpsServer*	server = tcp_client->server;

		server->kill_tcp_client(tcp_client, "TCP read error.");
	}

	/*****************************************************************************/
	/// TCP client accepted.
	static void
	listening_socket_handler(	int			fd,
				short			event,
				void*			_self)
	{
		GpsServer*	server = reinterpret_cast<GpsServer*>(_self);

		struct sockaddr_in	addr;
#ifdef WIN32
		int			addrlen = sizeof(addr);
#else
		socklen_t		addrlen = sizeof(addr);
#endif
		int			sd = accept(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrlen);
		if (sd == -1) {
			log("Error: Failed to get client.\n");
		} else {
			log("New client 0x%0x!", sd);
			TCP_CLIENT*		tcp_client = new TCP_CLIENT;
			tcp_client->fd	= sd;
			tcp_client->event = bufferevent_new(sd,
					tcp_client_read_handler,
					tcp_client_write_handler,
					tcp_client_error_handler,
					tcp_client);
			tcp_client->server	= server;
			tcp_client->mode	= CLIENTMODE_UNIDENTIFIED;
			tcp_client->idle_ticks	= 0;
			server->tcp_clients_.push_front(tcp_client);
			bufferevent_enable(tcp_client->event, EV_READ|EV_WRITE);

			// Stuff IDENIFY event..
			server->send_event(tcp_client, build_event(EVENTTYPE_IDENTIFY, ""));
		}
	}

public:
	/*****************************************************************************/
	/// Constructor - initialize to zero or reasonable defaults all stuff.
	GpsServer()
	:	config_concurrent_masters_(8),
		evb_(0),
		listening_socket_(INVALID_SOCKET),
		timer_count60_(0),
		timer_countping_(0)
	{
		try {
			load_winsock();
		} catch (const std::exception& e) {
			log("Error loading WinSock (%s), aborting.", e.what());
			throw;
		}
	}

	/*****************************************************************************/
	/// Destructor - release resources.
	~GpsServer()
	{
		unload_winsock();
	}

	/*****************************************************************************/
	/// Initalize & run server.
	void
	run()
	{
		// Initalize \c libevent.
		evb_ = reinterpret_cast<struct event_base*>(event_init());

		// Read configuration file.
		FileConfig	cfg(FILENAME_CONFIGURATION);
		cfg.load();
		cfg.set_section("GpsServer");
		// GpsServer.Masters
		{
			std::string			s;
			cfg.get_string("Masters", "", s);
			split(s, ",", config_masters_);
			log("Masters: %s", s.c_str());
		}
		// GpsServer.ConcurrentMasters
		cfg.get_uint("ConcurrentMasters", 8, config_concurrent_masters_);
		// Slave0, Slave1, ...
		{
			unsigned int	slaveno = 0;
			char		xbuf[1024];
			SLAVE_CONFIG	slave;
			for (;;++slaveno) {
				sprintf(xbuf, "Slave%d", slaveno);
				cfg.set_section(xbuf);
				if (cfg.get_string("ID", slave.id) && cfg.get_string("Name", slave.name)) {
					config_slaves_.push_back(slave);
					log("Slave: %s - %s", slave.name.c_str(), slave.id.c_str());
				} else {
					break;
				}
			}
		}
		log("Max. concurrent masters: %d", config_concurrent_masters_);

		// Open listening socket.
		listening_socket_ = open_server_socket(SERVER_PORT);
		log("Running on port %d", SERVER_PORT);
		event_set(&listening_socket_event_, listening_socket_, EV_READ|EV_PERSIST, listening_socket_handler,  this);
		event_add(&listening_socket_event_, 0);

		// Timer setup.
		event_set(&timer_event_, 0, EV_TIMEOUT|EV_PERSIST, timer_handler, this);
		timer_period_.tv_sec = 1;
		timer_period_.tv_usec = 0;
		timer_count60_ = 0;
		timer_countping_ = 0;
		evtimer_add(&timer_event_, &timer_period_);

		event_dispatch();
	}
};

/*****************************************************************************/
/// Set up listening port and start running...
int
main(	int	argc,
	char**	argv)
{
	TRACE_SETFILE("GpsServer-log.txt");
	try {
		GpsServer	server;
		server.run();
	} catch (const std::exception& e) {
		GpsServer::log("Exception: %s", e.what());
	}
	return 0;
}

