<?xml version="1.0" encoding="UTF-8"?>

<compiler_spec>
	<data_organization>
		<pointer_size value="4" />
		<short_size value="2" />
		<integer_size value="4" />
		<default_pointer_alignment value="4" />
		<default_alignment value="2" />
		<machine_alignment value="2" />
		<size_alignment_map>
          <entry size="1" alignment="1" />
          <entry size="2" alignment="2" />
          <entry size="4" alignment="4" />
          <entry size="8" alignment="4" />
     	</size_alignment_map>
	</data_organization>
	<global>
		<range space="mem"/>
	</global>
	<stackpointer register="SP" space="mem" growth="negative"/>
	<returnaddress>
		<register name="R14"/>
	</returnaddress>
	<default_proto>
	    <prototype name="__stdcall" extrapop="0" stackshift="0" strategy="register">
	        <input>
	        	<pentry minsize="1" maxsize="4" extension="inttype">
	        		<register name="R0"/>
	        	</pentry>
	        	<pentry minsize="1" maxsize="4" extension="inttype">
	        		<register name="R1"/>
	        	</pentry>
	        	<pentry minsize="1" maxsize="4" extension="inttype">
	        		<register name="R2"/>
	        	</pentry>
	        </input>
	        <output killedbycall="true">
	        	<pentry minsize="1" maxsize="4" extension="inttype">
	        		<register name="R0"/>
	        	</pentry>
	        </output>
			<unaffected>
				<register name="SP"/>
			</unaffected>
	    </prototype>
	</default_proto>
</compiler_spec>