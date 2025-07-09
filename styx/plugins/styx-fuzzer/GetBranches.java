// SPDX-License-Identifier: BSD-2-Clause
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.lang.Integer;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlock;

public class GetBranches extends GhidraScript {
    /*
        Gets all basic blocks (using SimpleBlockModel which includes calls as
        control flow changes) and writes all exit path source/destination pairs
        to a file, exluding fallthrough paths.
    */
    @Override
	public void run() throws Exception {
        File f = askFile("Enter file name, location to save results.", "OK");

        // a variable to keep track of how many branches exist
        int x = 0;

        try {
            if(f.createNewFile()) {
                println(String.format("File created: %s", f.getAbsolutePath()));
            }
            else {
                println("File exists already, contents will be overwritten.");
            }

            FileWriter file = new FileWriter(f, false);

            BasicBlockModel block_model = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = block_model.getCodeBlocks(monitor);

            for (CodeBlock block : blocks) {
                file.write(String.format("%d\n", block.getFirstStartAddress().getUnsignedOffset()));
                x++;
            }

            file.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        int power = Integer.SIZE - Integer.numberOfLeadingZeros(x - 1);

        println(String.format("Coverage map size: %d", 1 << power));
    }
}
