define mp_flags
	if $arg0->state == MP_STATE_NORMAL
		printf "NORMAL"
	end
	if $arg0->state == MP_STATE_INREORGQ
		printf "INREORGQ"
	end
	if $arg0->state == MP_STATE_PREREORG
		printf "PREREORG"
	end
	if $arg0->state == MP_STATE_REORGING
		printf "REORGING"
	end
	if $arg0->state == MP_STATE_DELETED
		printf "DELETED"
	end
end

define dp_flags
	if $arg0->flags & 0x1
		printf "DP_INTERNAL "
	end
	if $arg0->flags & 0x2
		printf "DP_LEAF "
	end
end

define list_pages
	set $i=0
	while $i < 102400
		printf "pgno: %d ", mp_pages[$i].pgno
		mp_flags mp_pages[$i]	
		printf " npg: %d count: %d ",mp_pages[$i].npg, mp_pages[$i].count
		
		if mp_pages[$i].dp
			if mp_pages[$i].flags & 0x1 
				printf "METADATA root_pgno: %d", mp_pages[$i].md.root_pgno
			else
				dp_flags mp_pages[$i].dp
				printf "lower: %d upper: %d", mp_pages[$i].dp.lower, mp_pages[$i].dp.upper
			end
		end
		printf "\n"
		set $i=$i+1
	end
end

define list_rec
	set $mp = (struct mpage *) $arg0
	set $dp = $mp->dp
	set $k = 0 
	set $count = ($dp->lower - 12) / 2

	while $k < $count
		if ($dp->flags & 0x1)
			set $p=(struct dinternal *)($mp->p + $dp->linp[$k])
			if ($p->ksize)
				printf "%02x", ((unsigned char *) ($p->bytes))[0]
				printf "%02x", ((unsigned char *) ($p->bytes))[1]
				printf "%02x", ((unsigned char *) ($p->bytes))[2]
				printf "%02x ",((unsigned char *) ($p->bytes))[3]
			else
				printf "%08x ", 0
			end
		else
			set $p=(DLEAF *) ($mp->p + $dp->linp[$k])
			printf "%02x", ((unsigned char *) ($p->bytes))[0]
			printf "%02x", ((unsigned char *) ($p->bytes))[1]
			printf "%02x", ((unsigned char *) ($p->bytes))[2]
			printf "%02x ",((unsigned char *) ($p->bytes))[3]
		end
		set $k=$k+1
	end
	printf "\n"
	set $k = 0 
	set $count = ($dp->lower - 12) / 2

	while $k < $count
		if ($dp->flags & 0x1)
			set $p=(struct dinternal *)($mp->p + $dp->linp[$k])
			printf "%8u ",  $p->pgno
		end
		set $k=$k+1
	end
	printf "\n"

end


