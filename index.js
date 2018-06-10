'use strict';

const
	crypto   = require('crypto'),
	farmhash = require('farmhash')
	;

const LN2_SQUARED = Math.LN2 * Math.LN2;

class FarmFilter
{
	constructor(options)
	{
		if (Buffer.isBuffer(options))
		{
			this.fromBuffer(options);
			return;
		}

		options = options || {};

		if (options.seeds)
		{
			this.seeds = options.seeds;
		}
		else
		{
			this.generateSeeds(options.hashes || 8);
		}

		this.bits = parseInt(options.bits, 10) || 1024;
		this.buffer = Buffer.alloc(Math.ceil(this.bits / 8));
	}

	static optimize(itemcount, errorRate)
	{
		errorRate = errorRate || 0.005;
		const bits = Math.round(-1 * itemcount * Math.log(errorRate) / LN2_SQUARED);
		const hashes = Math.round((bits / itemcount) * Math.LN2);
		return { bits, hashes };
	}

	static createOptimal(itemcount, errorRate)
	{
		const opts = FarmFilter.optimize(itemcount, errorRate);
		return new FarmFilter(opts);
	}

	clear()
	{
		this.buffer.fill(0);
	}

	generateSeeds(count)
	{
		let buf, j;
		this.seeds = [];

		for (let i = 0; i < count; i++)
		{
			buf = crypto.randomBytes(4);
			this.seeds[i] = buf.readUInt32LE(0);

			// Make sure we don't end up with two identical seeds,
			// which is unlikely but possible.
			for (j = 0; j < i; j++)
			{
				if (this.seeds[i] === this.seeds[j])
				{
					i--;
					break;
				}
			}
		}
	}

	setbit(bit)
	{
		let pos = 0;
		let shift = bit;
		while (shift > 7)
		{
			pos++;
			shift -= 8;
		}

		let bitfield = this.buffer[pos];
		bitfield |= (0x1 << shift);
		this.buffer[pos] = bitfield;
	}

	getbit(bit)
	{
		let pos = 0;
		let shift = bit;
		while (shift > 7)
		{
			pos++;
			shift -= 8;
		}

		const bitfield = this.buffer[pos];
		return (bitfield & (0x1 << shift)) !== 0;
	}

	_addOne(buf)
	{
		if (typeof buf === 'string')
			buf = Buffer.from(buf);

		for (let i = 0; i < this.seeds.length; i++)
		{
			const hash = farmhash.hash64WithSeed(buf, this.seeds[i]);
			const bit = hash % this.bits;
			this.setbit(bit);
		}
	}

	add(item)
	{
		if (Array.isArray(item))
		{
			for (let i = 0; i < item.length; i++)
				this._addOne(item[i]);
		}
		else
			this._addOne(item);
	}

	has(item)
	{
		if (typeof item === 'string')
			item = Buffer.from(item);

		for (let i = 0; i < this.seeds.length; i++)
		{
			const hash = farmhash.hash64WithSeed(item, this.seeds[i]);
			const bit = hash % this.bits;

			if (!this.getbit(bit))
				return false;
		}

		return true;
	}

	toBuffer()
	{
		// Wireline format is: a buffer structured in the following manner:
		// first byte: a version number
		// first 6 bytes: uint 16 containing # of bits
		// 7th byte: number of hash seeds, N (note lurking bug if ludicrous # of seeds)
		// followed by N x uint 32 LE seeds
		// remainder of buffer is the filter data
		// Note the fragility to change but also the brute-headed compactness.
		const buf = Buffer.alloc(1 + 6 + 1 + this.seeds.length * 4 + this.buffer.length);

		let ptr = 0;
		buf.writeUInt8(FarmFilter.VERSION, ptr++);
		buf.writeUIntLE(this.bits, ptr, 6);
		ptr += 6;
		buf.writeUInt8(this.seeds.length, ptr++);
		for (let i = 0; i < this.seeds.length; i++, ptr += 4)
		{
			buf.writeUInt32LE(this.seeds[i], ptr);
		}

		this.buffer.copy(buf, ptr);
		return buf;
	}

	fromBuffer(buf)
	{
		let ptr = 0;

		const version = buf.readUInt8(ptr++);
		// SWITCH ON VERSION HERE if necessary
		if (version !== FarmFilter.VERSION)
			return;

		this.bits = buf.readUIntLE(ptr, 6);
		ptr += 6;

		this.seeds = [];
		const seedcount = buf.readUInt8(ptr++);
		for (let i = 0; i < seedcount; i++, ptr += 4)
		{
			this.seeds[i] = buf.readUInt32LE(ptr);
		}

		this.buffer = Buffer.alloc(buf.length - 8 - (4 * seedcount));
		buf.copy(this.buffer, 0, ptr);
	}
}

FarmFilter.VERSION = 1;
module.exports = FarmFilter;
