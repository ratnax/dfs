define mp_flags
	if $arg0->state == MP_STATE_INIT
		printf "INIT"
	end
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
	if $arg0->flags & 0x2
		printf "DP_INTERNAL "
	end
	if $arg0->flags & 0x4
		printf "DP_LEAF "
	end
end

define list_pages2
	set $i=0
	while $i < 102400
		if  pages[$i]
		    set $mp=((struct mpage *) (&pages[$i].pgno))
		    printf "pgno: %d ", pages[$i].pgno
		    mp_flags $mp
		    printf " size: %d count: %d ",$mp->size, pages[$i].count
		
		    set $dp=$mp->dp	
		
		    if $dp.flags & 0x1 
				printf "METADATA root_pgno: %d", $dp.root_pgno
		    else
				dp_flags $dp
				printf "lower: %d upper: %d", $dp.lower, $dp.upper
		    end
		    printf "\n"
		else
	#	    printf "%ld deleted", $i
		end
	#	printf "\n"
		set $i=$i+1
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
	set $mp=$arg0
	set $dp=$mp->dp
	set $k = 0 
	set $count = ($dp->lower - 16) / 2 +1

	while $k < $count
		if ($dp->flags & 0x2)
			set $p=(struct dinternal *)((void *) $mp->dp + $dp->linp[$k])
			if ($p->ksize)
				printf "%02x", ((unsigned char *) ($p->bytes))[0]
				printf "%02x", ((unsigned char *) ($p->bytes))[1]
				printf "%02x", ((unsigned char *) ($p->bytes))[2]
				printf "%02x ",((unsigned char *) ($p->bytes))[3]
			else
				printf "%08x ", 0
			end
		else
			set $p=(DLEAF *) ((void *) $mp->dp + $dp->linp[$k])
			printf "%02x", ((unsigned char *) ($p->bytes))[0]
			printf "%02x", ((unsigned char *) ($p->bytes))[1]
			printf "%02x", ((unsigned char *) ($p->bytes))[2]
			printf "%02x ",((unsigned char *) ($p->bytes))[3]
		end
		set $k=$k+1
	end
	printf "\n"
	set $k = 0 
	set $count = ($dp->lower - 16) / 2+1

	while $k < $count
		if ($dp->flags & 0x2)
			set $p=(struct dinternal *)((void *) $mp->dp + $dp->linp[$k])
			printf "%8u ",  $p->pgno
		end
		set $k=$k+1
	end
	printf "\n"

end

define list_subtree
	set $mp_$arg1=$arg0
	set $dp_$arg1=$mp_$arg1->dp
	set $k_$arg1=0 
	set $count_$arg1=($dp_$arg1->lower - 12) / 2
	set $level_$arg1=$arg1+1
	
	if $dp_$arg1->flags & 0x1 
		printf "here\n"
		while $k_$arg1 < $count_$arg1
			set $p_$arg1=(struct dinternal *)($mp_$arg1->p + $dp_$arg1->linp[$k_$arg1])
			
			list_subtree &mp_pages[$p_$arg1->pgno] $level_$arg1 
			set $k_$arg1=$k_$arg1+1
		end

		printf "INTERNAL@%d:\n", $arg1
		set $k_$arg1 = 0 
		set $count_$arg1 = ($dp_$arg1->lower - 12) / 2
		while $k_$arg1 < $count_$arg1
			set $p_$arg1=(struct dinternal *)($mp_$arg1->p + $dp_$arg1->linp[$k_$arg1])

			if ($p_$arg1->ksize)
				printf "%02x", ((unsigned char *) ($p_$arg1->bytes))[0]
				printf "%02x", ((unsigned char *) ($p_$arg1->bytes))[1]
				printf "%02x", ((unsigned char *) ($p_$arg1->bytes))[2]
				printf "%02x ",((unsigned char *) ($p_$arg1->bytes))[3]
			else
				printf "%08x ", 0
			end
			set $k_$arg1=$k_$arg1+1
		end
		printf "\n"

		set $k_$arg1 = 0 
		set $count_$arg1 = ($dp_$arg1->lower - 12) / 2
		while $k_$arg1 < $count_$arg1
			set $p_$arg1=(struct dinternal *)($mp_$arg1->p + $dp_$arg1->linp[$k_$arg1])
			printf "%8u ",  $p_$arg1->pgno
			set $k_$arg1=$k_$arg1+1
		end
		printf "\n"
	else
		printf "LEAF@%d:\n", $arg1
		while $k_$arg1 < $count_$arg1
			set $p_$arg1=(DLEAF *) ($mp_$arg1->p + $dp_$arg1->linp[$k_$arg1])
			printf "%02x", ((unsigned char *) ($p_$arg1->bytes))[0]
			printf "%02x", ((unsigned char *) ($p_$arg1->bytes))[1]
			printf "%02x", ((unsigned char *) ($p_$arg1->bytes))[2]
			printf "%02x ",((unsigned char *) ($p_$arg1->bytes))[3]

			set $k_$arg1=$k_$arg1+1
		end
		printf "\n"
	end
end
			
define list_tree
	set $root_pgno=mp_pages[0].md.root_pgno
	set $mp=&mp_pages[$root_pgno]

	list_subtree $mp 0 
end
