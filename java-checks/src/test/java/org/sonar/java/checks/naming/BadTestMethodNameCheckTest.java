/*
 * SonarQube Java
 * Copyright (C) 2012-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.java.checks.naming;

import org.junit.Test;
import org.sonar.java.checks.verifier.JavaCheckVerifier;

import static org.sonar.java.CheckTestUtils.testSourcesPath;

public class BadTestMethodNameCheckTest {

  @Test
  public void test() {
    BadTestMethodNameCheck check = new BadTestMethodNameCheck();
    JavaCheckVerifier.verify("src/test/files/checks/naming/BadTestMethodNameCheck.java", check);
    // test with same instance to cover reuse of regexp pattern (lazy initialization).
    JavaCheckVerifier.verify("src/test/files/checks/naming/BadTestMethodNameCheck.java", check);

    JavaCheckVerifier.verifyNoIssueWithoutSemantic("src/test/files/checks/naming/BadTestMethodNameCheck.java", check);
  }

  @Test
  public void test_with_customPattern() {
    BadTestMethodNameCheck check = new BadTestMethodNameCheck();
    check.format = "^test_sonar[A-Z][a-zA-Z0-9]*$";
    JavaCheckVerifier.verify(testSourcesPath("checks/naming/BadTestMethodNameCheckCustom.java"), check);
  }

}
