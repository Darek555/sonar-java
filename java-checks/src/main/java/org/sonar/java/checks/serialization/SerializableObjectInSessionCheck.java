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
package org.sonar.java.checks.serialization;

import java.util.Collections;
import java.util.List;
import org.sonar.check.Rule;
import org.sonar.java.checks.helpers.ExpressionsHelper;
import org.sonar.java.checks.methods.AbstractMethodDetection;
import org.sonar.java.matcher.MethodMatcher;
import org.sonar.java.matcher.TypeCriteria;
import org.sonar.java.model.JUtils;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;

@Rule(key = "S2441")
public class SerializableObjectInSessionCheck extends AbstractMethodDetection {

  @Override
  protected List<MethodMatcher> getMethodInvocationMatchers() {
    return Collections.singletonList(MethodMatcher.create().typeDefinition("javax.servlet.http.HttpSession")
      .name("setAttribute").addParameter("java.lang.String").addParameter(TypeCriteria.anyType()));
  }

  @Override
  protected void onMethodInvocationFound(MethodInvocationTree mit) {
    ExpressionTree argument = mit.arguments().get(1);
    Type type = argument.symbolType();
    if (ExpressionsHelper.isNotSerializable(argument)) {
      String andParameters = JUtils.isParametrized(type) ? " and its parameters" : "";
      reportIssue(argument, "Make \"" + type.name() + "\"" + andParameters + " serializable or don't store it in the session.");
    }
  }

}
