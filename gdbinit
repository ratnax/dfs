define mp_flags
	if $arg0->flags & 0x1
		printf "MP_DIRTY "
	end
	if $arg0->flags & 0x2
		printf "MP_SPLITTING "
	end
	if $arg0->flags & 0X4
		printf "MP_LEFTMOST "
	end
	if $arg0->flags & 0x8
		printf "MP_RIGHTMOST "
	end
	if $arg0->flags & 0x10
		printf "MP_BIGPAGE "
	end
	if $arg0->flags & 0x20
		printf "MP_METADATA "
	end
	if $arg0->flags & 0x40
		printf "MP_DELETING "	
	end
	if $arg0->flags & 0x80
		printf "MP_DELETED "	
	end
	if $arg0->flags & 0x100
		printf "MP_INSPLQ "	
	end
	if $arg0->flags & 0x200
		printf "MP_INDELQ "	
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
		printf "npg: %d count: %d ",mp_pages[$i].npg, mp_pages[$i].count
		
		if mp_pages[$i].dp
			if mp_pages[$i].flags & 0x20 
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
				printf "%8u ", *(unsigned int*) ($p->bytes)
			else
				printf "%8u ", 0
			end
		else
			set $p=(DLEAF *) ($mp->p + $dp->linp[$k])
			printf "%u ", *(unsigned int*) ($p->bytes)
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


