package redisStorage

import "github.com/redis/go-redis/v9"

var setNewTokenScript = redis.NewScript(`
	if redis.call("EXISTS", KEYS[1]) == 1 then
		redis.call("RENAME", KEYS[1], KEYS[2])
		redis.call("EXPIRE", KEYS[2], ARGV[1])
		return 1
	end
	return 0
`)

var saveRefreshTokenScript = redis.NewScript(`
	redis.call("HSET", KEYS[1], "uid", ARGV[1], "aid", ARGV[2])
	redis.call("EXPIRE", KEYS[1], ARGV[3])
	return 1
`)