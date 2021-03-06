/*global describe:true, it:true, before:true, after:true */

const
	demand = require('must'),
	Farmfilter = require('./index')
	;

function hasBitsSet(buffer)
{
	let isset = 0;
	for (let i = 0; i < buffer.length; i++)
		isset |= (buffer[i] !== 0);
	return isset;
}

describe('FarmFilter()', () =>
{
	it('constructs a filter of the requested size', () =>
	{
		const filter = new Farmfilter({ hashes: 4, bits: 32 });
		filter.seeds.length.must.equal(4);
		filter.bits.must.equal(32);
		filter.bits.must.equal(32);
		Buffer.isBuffer(filter.buffer).must.be.true();
	});

	it('zeroes out its storage buffer', () =>
	{
		const filter = new Farmfilter({ hashes: 3, bits: 64 });
		for (let i = 0; i < filter.buffer.length; i++)
			filter.buffer[i].must.equal(0);
	});

	it('uses passed-in seeds if provided', () =>
	{
		const filter = new Farmfilter({ bits: 256, seeds: [1, 2, 3, 4, 5]});
		filter.seeds.length.must.equal(5);
		filter.seeds[0].must.equal(1);
		filter.seeds[4].must.equal(5);
	});

	describe('createOptimal()', () =>
	{
		it('creates a filter with good defaults', () =>
		{
			let filter = Farmfilter.createOptimal(95);
			filter.bits.must.equal(1048);
			filter.seeds.length.must.equal(8);

			filter = Farmfilter.createOptimal(148);
			filter.bits.must.equal(1632);
			filter.seeds.length.must.equal(8);

			filter = Farmfilter.createOptimal(10);
			filter.bits.must.equal(110);
			filter.seeds.length.must.equal(8);
		});

		it('createOptimal() lets you specify an error rate', () =>
		{
			let filter = Farmfilter.createOptimal(20000);
			filter.bits.must.equal(220555);
			const previous = filter.bits;

			filter = Farmfilter.createOptimal(20000, 0.2);
			filter.bits.must.be.below(previous);
		});
	});

	describe('setbit() and getbit()', () =>
	{
		it('sets the specified bit', () =>
		{
			const filter = new Farmfilter({ hashes: 3, bits: 16 });

			filter.setbit(0);
			let val = filter.getbit(0);
			val.must.equal(true);

			filter.setbit(1);
			val = filter.getbit(1);
			val.must.equal(true);

			val = filter.getbit(2);
			val.must.equal(false);

			filter.setbit(10);
			val = filter.getbit(10);
			val.must.equal(true);
		});

		it('can set all bits', () =>
		{
			let i, value;

			const filter = new Farmfilter({ hashes: 3, bits: 16 });
			filter.buffer.length.must.equal(2);

			for (i = 0; i < 16; i++)
				filter.setbit(i);

			for (i = 0; i < 2; i++)
			{
				value = filter.buffer[i];
				value.must.equal(255);
			}
		});

		it('slides over into the next buffer slice when setting bits', () =>
		{
			let val;
			const filter = new Farmfilter({ hashes: 3, bits: 64 });

			filter.setbit(8);
			val = filter.buffer[1];
			val.must.equal(1);

			filter.setbit(17);
			val = filter.buffer[2];
			val.must.equal(2);

			filter.setbit(34);
			val = filter.buffer[4];
			val.must.equal(4);
		});
	});

	describe('add()', () =>
	{
		it('can store buffers', () =>
		{
			const filter = new Farmfilter({ hashes: 4, bits: 128 });

			hasBitsSet(filter.buffer).must.equal(0);
			filter.add(Buffer.from('cat'));
			hasBitsSet(filter.buffer).must.equal(1);
		});

		it('can store strings', () =>
		{
			const filter = new Farmfilter({ hashes: 4, bits: 128 });
			filter.add('cat');

			hasBitsSet(filter.buffer).must.equal(1);
		});

		it('can store arrays of buffers or strings', () =>
		{
			const filter = new Farmfilter({ hashes: 4, bits: 128 });
			filter.add(['cat', 'dog', 'wallaby']);

			hasBitsSet(filter.buffer).must.equal(1);
		});

		it('can add a hundred random items', () =>
		{
			const alpha = '0123456789abcdefghijklmnopqrstuvwxyz';
			function randomWord(length)
			{
				length = length || Math.ceil(Math.random() * 20);
				let result = '';
				for (let i = 0; i < length; i++)
					result += alpha[Math.floor(Math.random() * alpha.length)];

				return result;
			}

			const filter = Farmfilter.createOptimal(100);
			const words = [];
			for (let i = 0; i < 100; i++)
			{
				const w = randomWord();
				words.push(w);
				filter.add(w);
			}

			for (let i = 0; i < words.length; i++)
				filter.has(words[i]).must.equal(true);
		});

	});

	describe('has()', () =>
	{
		it('returns true when called on a stored item', () =>
		{
			const filter = new Farmfilter({ hashes: 3, bits: 16 });
			filter.add('cat');

			hasBitsSet(filter.buffer).must.equal(1);
			filter.has('cat').must.be.true();
		});

		it('returns false for items not in the set (mostly)', () =>
		{
			const filter = new Farmfilter({ hashes: 4, bits: 50 });
			filter.add('cat');
			filter.has('dog').must.be.false();
		});

		it('responds appropriately for arrays of added items', () =>
		{
			const filter = Farmfilter.createOptimal(20);
			filter.add(['cat', 'dog', 'wallaby']);

			filter.has('cat').must.equal(true);
			filter.has('dog').must.equal(true);
			filter.has('wallaby').must.equal(true);
			filter.has('orange').must.equal(false);
		});
	});

	describe('clear()', () =>
	{
		it('clears the filter', () =>
		{
			const filter = new Farmfilter({ hashes: 3, bits: 128 });
			filter.add(['cat', 'dog', 'wallaby']);
			hasBitsSet(filter.buffer).must.equal(1);

			filter.clear();
			hasBitsSet(filter.buffer).must.equal(0);
		});
	});

	describe('wireline format', () =>
	{
		it('toBuffer() returns a buffer', () =>
		{
			const filter = new Farmfilter({ hashes: 3, bits: 128 });
			filter.add(['cat', 'dog', 'wallaby']);
			const buf = filter.toBuffer();

			buf.readUInt8(0).must.equal(Farmfilter.VERSION);
			buf.readUIntLE(1, 6).must.equal(128);
			buf.readUInt8(7).must.equal(3);
			buf.readUInt32LE(8).must.equal(filter.seeds[0]);
			buf.readUInt32LE(12).must.equal(filter.seeds[1]);
			buf.readUInt32LE(16).must.equal(filter.seeds[2]);

			for (let i = 0; i < filter.buffer.length; i++)
			{
				buf[i + 20].must.equal(filter.buffer[i]);
			}
		});

		it('fromBuffer() reconstructs the filter', () =>
		{
			const filter = new Farmfilter({ hashes: 3, bits: 128 });
			filter.add(['cat', 'dog', 'wallaby']);
			const buf = filter.toBuffer();

			const copy = new Farmfilter(buf);

			copy.bits.must.equal(filter.bits);
			copy.seeds.length.must.equal(filter.seeds.length);

			for (let i = 0; i < filter.seeds.length; i++)
			{
				copy.seeds[i].must.equal(filter.seeds[i]);
			}

			const cmp = copy.buffer.compare(filter.buffer);
			cmp.must.equal(0);

			const animals = ['cat', 'dog', 'wallaby', 'wombat', 'frog', 'quokka'];
			animals.forEach(a =>
			{
				copy.has(a).must.equal(filter.has(a));
			});
		});
	});
});
