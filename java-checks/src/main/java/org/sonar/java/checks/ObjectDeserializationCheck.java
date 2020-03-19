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
package org.sonar.java.checks;

import org.sonar.check.Rule;
import org.sonar.java.checks.methods.AbstractMethodDetection;
import org.sonar.java.matcher.MethodMatcher;
import org.sonar.java.matcher.TypeCriteria;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;

@Rule(key = "S4508")
public class ObjectDeserializationCheck extends AbstractMethodDetection {

  private static final String OBJECT_INPUT_STREAM = "java.io.ObjectInputStream";
  private static final String MESSAGE = "Make sure deserializing objects is safe here.";

  @Override
  protected MethodMatchers getMethodInvocationMatchers() {
    return MethodMatchers.or(
      MethodMatcher.create().ofType(TypeCriteria.subtypeOf(OBJECT_INPUT_STREAM)).names("readObject").addWithoutParametersMatcher(),
      MethodMatcher.create().ofType(TypeCriteria.subtypeOf(OBJECT_INPUT_STREAM)).names("readUnshared").addWithoutParametersMatcher()
    );
  }

  @Override
  protected void onMethodInvocationFound(MethodInvocationTree mit) {
    reportIssue(mit, MESSAGE);
  }
}
